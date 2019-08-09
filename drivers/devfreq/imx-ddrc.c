// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 NXP
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/devfreq.h>
#include <linux/pm_opp.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/arm-smccc.h>

#include <asm/perf_event.h>
#include <linux/perf_event.h>

#define IMX_SIP_DDR_DVFS			0xc2000004

/* Values starting from 0 switch to specific frequency */
#define IMX_SIP_DDR_FREQ_SET_HIGH		0x00

/* Deprecated after moving IRQ handling to ATF */
#define IMX_SIP_DDR_DVFS_WAIT_CHANGE		0x0F

/* Query available frequencies. */
#define IMX_SIP_DDR_DVFS_GET_FREQ_COUNT		0x10
#define IMX_SIP_DDR_DVFS_GET_FREQ_INFO		0x11

/*
 * This should be in a 1:1 mapping with devicetree OPPs but
 * firmware provides additional info.
 */
struct imx_ddrc_freq {
	unsigned long rate;
	unsigned long smcarg;
	int dram_core_parent_index;
	int dram_alt_parent_index;
	int dram_apb_parent_index;
};

/* Hardware limitation */
#define IMX_DDRC_MAX_FREQ_COUNT 4

/*
 * imx DRAM controller
 *
 * imx DRAM controller clocks have the following structure (abridged):
 *
 * +----------+       |\            +------+
 * | dram_pll |-------|M| dram_core |      |
 * +----------+       |U|---------->| D    |
 *                 /--|X|           |  D   |
 *   dram_alt_root |  |/            |   R  |
 *                 |                |    C |
 *            +---------+           |      |
 *            |FIX DIV/4|           |      |
 *            +---------+           |      |
 *  composite:     |                |      |
 * +----------+    |                |      |
 * | dram_alt |----/                |      |
 * +----------+                     |      |
 * | dram_apb |-------------------->|      |
 * +----------+                     +------+
 *
 * The dram_pll is used for higher rates and dram_alt is used for lower rates.
 *
 * Frequency switching is implemented in TF-A (via SMC call) and can change the
 * configuration of the clocks, including mux parents. The dram_alt and
 * dram_apb clocks are "imx composite" and their parent can change too.
 *
 * We need to prepare/enable the new mux parents head of switching and update
 * their information afterwards.
 */
struct imx_ddrc {
	struct devfreq_dev_profile profile;
	struct devfreq *devfreq;

	/* For frequency switching: */
	struct clk *dram_core;
	struct clk *dram_pll;
	struct clk *dram_alt;
	struct clk *dram_apb;

	int freq_count;
	struct imx_ddrc_freq freq_table[IMX_DDRC_MAX_FREQ_COUNT];

	/* For measuring load with perf events: */
	struct platform_device *pmu_pdev;
	struct pmu *pmu;

	struct perf_event_attr rd_event_attr;
	struct perf_event_attr wr_event_attr;
	struct perf_event *rd_event;
	struct perf_event *wr_event;

	u64 last_rd_val, last_rd_ena, last_rd_run;
	u64 last_wr_val, last_wr_ena, last_wr_run;
};

static struct imx_ddrc_freq *imx_ddrc_find_freq(struct imx_ddrc *priv,
						unsigned long rate)
{
	int i;

	/*
	 * Firmware reports values in MT/s, so we round-down from Hz
	 * Rounding is extra generous to ensure a match.
	 */
	rate = DIV_ROUND_CLOSEST(rate, 250000);
	for (i = 0; i < priv->freq_count; ++i) {
		struct imx_ddrc_freq *freq = &priv->freq_table[i];
		if (freq->rate == rate ||
				freq->rate + 1 == rate ||
				freq->rate - 1 == rate)
			return freq;
	}

	return NULL;
}

static void imx_ddrc_smc_set_freq(int target_freq)
{
	struct arm_smccc_res res;
	u32 online_cpus = 0;
	int cpu;

	local_irq_disable();

	for_each_online_cpu(cpu)
		online_cpus |= (1 << (cpu * 8));

	/* change the ddr freqency */
	arm_smccc_smc(IMX_SIP_DDR_DVFS, target_freq, online_cpus,
			0, 0, 0, 0, 0, &res);

	local_irq_enable();
}

struct clk *clk_get_parent_by_index(struct clk *clk, int index)
{
	struct clk_hw *hw;

	hw = clk_hw_get_parent_by_index(__clk_get_hw(clk), index);

	return hw ? hw->clk : NULL;
}

static int imx_ddrc_set_freq(struct device *dev, struct imx_ddrc_freq *freq)
{
	struct imx_ddrc *priv = dev_get_drvdata(dev);
	struct clk *new_dram_core_parent;
	struct clk *new_dram_alt_parent;
	struct clk *new_dram_apb_parent;
	int ret;

	new_dram_core_parent = clk_get_parent_by_index(
			priv->dram_core, freq->dram_core_parent_index - 1);
	new_dram_alt_parent = clk_get_parent_by_index(
			priv->dram_alt, freq->dram_alt_parent_index - 1);
	new_dram_apb_parent = clk_get_parent_by_index(
			priv->dram_apb, freq->dram_apb_parent_index - 1);

	/* increase reference counts and ensure clks are ON before switch */
	ret = clk_prepare_enable(new_dram_core_parent);
	if (ret) {
		dev_err(dev, "failed enable new dram_core parent: %d\n", ret);
		goto out;
	}
	ret = clk_prepare_enable(new_dram_alt_parent);
	if (ret) {
		dev_err(dev, "failed enable new dram_alt parent: %d\n", ret);
		goto out_dis_core;
	}
	ret = clk_prepare_enable(new_dram_apb_parent);
	if (ret) {
		dev_err(dev, "failed enable new dram_apb parent: %d\n", ret);
		goto out_dis_alt;
	}

	imx_ddrc_smc_set_freq(freq->smcarg);

	/* update parents in clk tree after switch. */
	ret = clk_set_parent(priv->dram_core, new_dram_core_parent);
	if (ret)
		dev_err(dev, "failed set dram_core parent: %d\n", ret);
	if (new_dram_alt_parent) {
		ret = clk_set_parent(priv->dram_alt, new_dram_alt_parent);
		if (ret)
			dev_err(dev, "failed set dram_alt parent: %d\n", ret);
	}
	if (new_dram_apb_parent) {
		ret = clk_set_parent(priv->dram_apb, new_dram_apb_parent);
		if (ret)
			dev_err(dev, "failed set dram_apb parent: %d\n", ret);
	}

	/*
	 * Explicitly refresh dram PLL rate.
	 *
	 * Even if it's marked with CLK_GET_RATE_NOCACHE the rate will not be
	 * automatically refreshed when clk_get_rate is called on children.
	 */
	clk_get_rate(priv->dram_pll);

	/*
	 * clk_set_parent transfer the reference count from old parent.
	 * now we drop extra reference counts used during the switch
	 */
	clk_disable_unprepare(new_dram_apb_parent);
out_dis_alt:
	clk_disable_unprepare(new_dram_alt_parent);
out_dis_core:
	clk_disable_unprepare(new_dram_core_parent);
out:
	return ret;
}

static int imx_ddrc_target(struct device *dev, unsigned long *freq, u32 flags)
{
	struct imx_ddrc *priv = dev_get_drvdata(dev);
	struct imx_ddrc_freq *freq_info;
	struct dev_pm_opp *new_opp;
	unsigned long old_freq, new_freq;
	int ret;

	new_opp = devfreq_recommended_opp(dev, freq, flags);
	if (IS_ERR(new_opp)) {
		ret = PTR_ERR(new_opp);
		dev_err(dev, "failed to get recommended opp: %d\n", ret);
		return ret;
	}
	dev_pm_opp_put(new_opp);

	old_freq = clk_get_rate(priv->dram_core);
	if (*freq == old_freq)
		return 0;

	freq_info = imx_ddrc_find_freq(priv, *freq);
	if (!freq_info)
		return -EINVAL;
	ret = imx_ddrc_set_freq(dev, freq_info);

	/* Also read back the clk rate to verify switch was correct */
	new_freq = clk_get_rate(priv->dram_core);
	if (ret || *freq != new_freq)
		dev_err(dev, "ddrc failed to change freq %lu to %lu: now at %lu\n",
				old_freq, *freq, new_freq);
	else
		dev_dbg(dev, "ddrc changed freq %lu to %lu\n",
				old_freq, *freq);

	return ret;
}

static int imx_ddrc_get_cur_freq(struct device *dev, unsigned long *freq)
{
	struct imx_ddrc *priv = dev_get_drvdata(dev);

	*freq = clk_get_rate(priv->dram_core);

	return 0;
}

static int imx_ddrc_get_dev_status(struct device *dev,
				   struct devfreq_dev_status *stat)
{
	struct imx_ddrc *priv = dev_get_drvdata(dev);

	stat->current_frequency = clk_get_rate(priv->dram_core);

	if (priv->rd_event && priv->wr_event) {
		u64 rd_delta, rd_val, rd_ena, rd_run;
		u64 wr_delta, wr_val, wr_ena, wr_run;

		rd_val = perf_event_read_value(priv->rd_event,
					       &rd_ena, &rd_run);
		wr_val = perf_event_read_value(priv->wr_event,
					       &wr_ena, &wr_run);

		rd_delta = (rd_val - priv->last_rd_val) *
			   (rd_ena - priv->last_rd_ena);
		do_div(rd_delta, rd_run - priv->last_rd_run);
		priv->last_rd_val = rd_val;
		priv->last_rd_ena = rd_ena;
		priv->last_rd_run = rd_run;

		wr_delta = (wr_val - priv->last_wr_val) *
			   (wr_ena - priv->last_wr_ena);
		do_div(wr_delta, wr_run - priv->last_wr_run);
		priv->last_wr_val = wr_val;
		priv->last_wr_ena = wr_ena;
		priv->last_wr_run = wr_run;

		/* magic numbers, possibly wrong */
		stat->busy_time = 4 * (rd_delta + wr_delta);
		stat->total_time = stat->current_frequency;
	} else {
		stat->busy_time = 0;
		stat->total_time = 0;
	}

	return 0;
}

static int imx_ddrc_perf_disable(struct imx_ddrc *priv)
{
	/* release and set to NULL */
	if (!IS_ERR_OR_NULL(priv->rd_event))
		perf_event_release_kernel(priv->rd_event);
	if (!IS_ERR_OR_NULL(priv->wr_event))
		perf_event_release_kernel(priv->wr_event);
	priv->rd_event = NULL;
	priv->wr_event = NULL;

	return 0;
}

static int imx_ddrc_perf_enable(struct imx_ddrc *priv)
{
	int ret;

	priv->rd_event_attr.size = sizeof(priv->rd_event_attr);
	priv->rd_event_attr.type = priv->pmu->type;
	priv->rd_event_attr.config = 0x2a;

	priv->rd_event = perf_event_create_kernel_counter(
			&priv->rd_event_attr, 0, NULL, NULL, NULL);
	if (IS_ERR(priv->rd_event)) {
		ret = PTR_ERR(priv->rd_event);
		goto err;
	}

	priv->wr_event_attr.size = sizeof(priv->wr_event_attr);
	priv->wr_event_attr.type = priv->pmu->type;
	priv->wr_event_attr.config = 0x2b;

	priv->wr_event = perf_event_create_kernel_counter(
			&priv->wr_event_attr, 0, NULL, NULL, NULL);
	if (IS_ERR(priv->wr_event)) {
		ret = PTR_ERR(priv->wr_event);
		goto err;
	}

	return 0;

err:
	imx_ddrc_perf_disable(priv);
	return ret;
}

static int imx_ddrc_init_events(struct device *dev,
				struct device_node *events_node)
{
	struct imx_ddrc *priv = dev_get_drvdata(dev);
	struct device_driver *driver;

	/*
	 * We need pmu->type for perf_event_attr but there is no API for
	 * mapping device_node to pmu. Fetch private data for imx-ddr-pmu and
	 * cast that to a struct pmu instead.
	 */
	priv->pmu_pdev = of_find_device_by_node(events_node);
	if (!priv->pmu_pdev)
		return -EPROBE_DEFER;
	driver = priv->pmu_pdev->dev.driver;
	if (!driver)
		return -EPROBE_DEFER;
	if (strcmp(driver->name, "imx-ddr-pmu")) {
		dev_warn(dev, "devfreq-events node %pOF has unexpected driver %s\n",
				events_node, driver->name);
		return -ENODEV;
	}

	priv->pmu = platform_get_drvdata(priv->pmu_pdev);
	if (!priv->pmu) {
		dev_err(dev, "devfreq-events device missing private data\n");
		return -EINVAL;
	}

	dev_dbg(dev, "events from pmu %s\n", priv->pmu->name);

	return imx_ddrc_perf_enable(priv);
}

static int imx_ddrc_init_freq_info(struct device *dev)
{
	struct imx_ddrc *priv = dev_get_drvdata(dev);
	struct arm_smccc_res res;
	int index;

	/*
	 * An error here means DDR DVFS API not supported by firmware
	 */
	arm_smccc_smc(IMX_SIP_DDR_DVFS, IMX_SIP_DDR_DVFS_GET_FREQ_COUNT,
			0, 0, 0, 0, 0, 0, &res);
	priv->freq_count = res.a0;
	if (priv->freq_count <= 0 || priv->freq_count > IMX_DDRC_MAX_FREQ_COUNT)
		return -ENODEV;

	for (index = 0; index < priv->freq_count; ++index) {
		struct imx_ddrc_freq *freq = &priv->freq_table[index];

		arm_smccc_smc(IMX_SIP_DDR_DVFS, IMX_SIP_DDR_DVFS_GET_FREQ_INFO,
				index, 0, 0, 0, 0, 0, &res);
		/* Result should be strictly positive */
		if ((long)res.a0 <= 0)
			return -ENODEV;

		freq->rate = res.a0;
		freq->smcarg = index;
		freq->dram_core_parent_index = res.a1;
		freq->dram_alt_parent_index = res.a2;
		freq->dram_apb_parent_index = res.a3;

		/* dram_core has 2 options: dram_pll or dram_alt_root */
		if (freq->dram_core_parent_index != 1 &&
				freq->dram_core_parent_index != 2)
			return -ENODEV;
		/* dram_apb and dram_alt have exactly 8 possible parents */
		if (freq->dram_alt_parent_index > 8 ||
				freq->dram_apb_parent_index > 8)
			return -ENODEV;
		/* dram_core from alt requires explicit dram_alt parent */
		if (freq->dram_core_parent_index == 2 &&
				freq->dram_alt_parent_index == 0)
			return -ENODEV;
	}

	return 0;
}

/* imx_ddrc_check_opps() - disable OPPs not supported by firmware */
static int imx_ddrc_check_opps(struct device *dev)
{
	struct imx_ddrc *priv = dev_get_drvdata(dev);
	struct imx_ddrc_freq *freq_info;
	struct dev_pm_opp *opp;
	unsigned long freq;

	freq = ULONG_MAX;
	while (true) {
		opp = dev_pm_opp_find_freq_floor(dev, &freq);
		if (opp == ERR_PTR(-ERANGE))
			break;
		if (IS_ERR(opp)) {
			dev_err(dev, "Failed enumerating OPPs: %ld\n",
				PTR_ERR(opp));
			return PTR_ERR(opp);
		}
		dev_pm_opp_put(opp);

		freq_info = imx_ddrc_find_freq(priv, freq);
		if (!freq_info) {
			dev_info(dev, "Disable unsupported OPP %luHz %luMT/s\n",
					freq, DIV_ROUND_CLOSEST(freq, 250000));
			dev_pm_opp_disable(dev, freq);
		}

		freq--;
	}

	return 0;
}

static void imx_ddrc_exit(struct device *dev)
{
	struct imx_ddrc *priv = dev_get_drvdata(dev);

	imx_ddrc_perf_disable(priv);
	platform_device_put(priv->pmu_pdev);

	dev_pm_opp_of_remove_table(dev);
}

static int imx_ddrc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct imx_ddrc *priv;
	struct device_node *events_node;
	const char *gov = DEVFREQ_GOV_USERSPACE;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	platform_set_drvdata(pdev, priv);

	ret = imx_ddrc_init_freq_info(dev);
	if (ret) {
		dev_err(dev, "failed to init firmware freq info: %d\n", ret);
		return ret;
	}

	events_node = of_parse_phandle(dev->of_node, "devfreq-events", 0);
	if (events_node) {
		ret = imx_ddrc_init_events(dev, events_node);
		of_node_put(events_node);
		if (ret)
			goto err;
		gov = DEVFREQ_GOV_SIMPLE_ONDEMAND;
	}

	priv->dram_core = devm_clk_get(dev, "dram_core");
	priv->dram_pll = devm_clk_get(dev, "dram_pll");
	priv->dram_alt = devm_clk_get(dev, "dram_alt");
	priv->dram_apb = devm_clk_get(dev, "dram_apb");
	if (IS_ERR(priv->dram_core) ||
		IS_ERR(priv->dram_pll) ||
		IS_ERR(priv->dram_alt) ||
		IS_ERR(priv->dram_apb)) {
		ret = PTR_ERR(priv->devfreq);
		dev_err(dev, "failed to fetch clocks: %d\n", ret);
		return ret;
	}

	ret = dev_pm_opp_of_add_table(dev);
	if (ret < 0) {
		dev_err(dev, "failed to get OPP table\n");
		return ret;
	}

	ret = imx_ddrc_check_opps(dev);
	if (ret < 0)
		goto err;

	priv->profile.polling_ms = 1000;
	priv->profile.target = imx_ddrc_target;
	priv->profile.get_dev_status = imx_ddrc_get_dev_status;
	priv->profile.exit = imx_ddrc_exit;
	priv->profile.get_cur_freq = imx_ddrc_get_cur_freq;
	priv->profile.initial_freq = clk_get_rate(priv->dram_core);

	priv->devfreq = devm_devfreq_add_device(dev, &priv->profile,
						gov, NULL);
	if (IS_ERR(priv->devfreq)) {
		ret = PTR_ERR(priv->devfreq);
		dev_err(dev, "failed to add devfreq device: %d\n", ret);
		goto err;
	}

	return 0;

err:
	imx_ddrc_perf_disable(priv);
	platform_device_put(priv->pmu_pdev);
	dev_pm_opp_of_remove_table(dev);
	return ret;
}

static const struct of_device_id imx_ddrc_of_match[] = {
	{ .compatible = "fsl,imx8m-ddrc", },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, imx_ddrc_of_match);

static struct platform_driver imx_ddrc_platdrv = {
	.probe		= imx_ddrc_probe,
	.driver = {
		.name	= "imx-ddrc-devfreq",
		.of_match_table = of_match_ptr(imx_ddrc_of_match),
	},
};
module_platform_driver(imx_ddrc_platdrv);

MODULE_DESCRIPTION("i.MX DDR controller frequency driver");
MODULE_AUTHOR("Leonard Crestez <leonard.crestez@nxp.com>");
MODULE_LICENSE("GPL v2");
