// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 NXP
 */

#include <linux/clk.h>
#include <linux/devfreq.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/pm_opp.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

struct imx_devfreq {
	struct devfreq_dev_profile profile;
	struct devfreq *devfreq;
	struct clk *clk;
	struct devfreq_passive_data passive_data;
};

static int imx_devfreq_target(struct device *dev, unsigned long *freq, u32 flags)
{
	struct imx_devfreq *priv = dev_get_drvdata(dev);
	struct dev_pm_opp *new_opp;
	unsigned long new_freq;
	int ret;

	new_opp = devfreq_recommended_opp(dev, freq, flags);
	if (IS_ERR(new_opp)) {
		ret = PTR_ERR(new_opp);
		dev_err(dev, "failed to get recommended opp: %d\n", ret);
		return ret;
	}
	new_freq = dev_pm_opp_get_freq(new_opp);
	dev_pm_opp_put(new_opp);

	return clk_set_rate(priv->clk, new_freq);
}

static int imx_devfreq_get_cur_freq(struct device *dev, unsigned long *freq)
{
	struct imx_devfreq *priv = dev_get_drvdata(dev);

	*freq = clk_get_rate(priv->clk);

	return 0;
}

static int imx_devfreq_get_dev_status(struct device *dev,
		struct devfreq_dev_status *stat)
{
	struct imx_devfreq *priv = dev_get_drvdata(dev);

	stat->busy_time = 0;
	stat->total_time = 0;
	stat->current_frequency = clk_get_rate(priv->clk);

	return 0;
}

static void imx_devfreq_exit(struct device *dev)
{
	dev_pm_opp_of_remove_table(dev);
}

static int imx_devfreq_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct imx_devfreq *priv;
	const char *gov = DEVFREQ_GOV_USERSPACE;
	void *govdata = NULL;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(priv->clk)) {
		ret = PTR_ERR(priv->clk);
		dev_err(dev, "failed to fetch clk: %d\n", ret);
		return ret;
	}
	platform_set_drvdata(pdev, priv);

	ret = dev_pm_opp_of_add_table(dev);
	if (ret < 0) {
		dev_err(dev, "failed to get OPP table\n");
		return ret;
	}

	priv->profile.polling_ms = 1000;
	priv->profile.target = imx_devfreq_target;
	priv->profile.get_dev_status = imx_devfreq_get_dev_status;
	priv->profile.exit = imx_devfreq_exit;
	priv->profile.get_cur_freq = imx_devfreq_get_cur_freq;
	priv->profile.initial_freq = clk_get_rate(priv->clk);

	/* Handle passive devfreq parent link */
	priv->passive_data.parent = devfreq_get_devfreq_by_phandle(dev, 0);
	if (!IS_ERR(priv->passive_data.parent)) {
		dev_info(dev, "passive link to %s\n",
				dev_name(priv->passive_data.parent->dev.parent));
		gov = DEVFREQ_GOV_PASSIVE;
		govdata = &priv->passive_data;
	} else if (priv->passive_data.parent != ERR_PTR(-ENODEV)) {
		// -ENODEV means no parent: not an error.
		ret = PTR_ERR(priv->passive_data.parent);
		if (ret != -EPROBE_DEFER)
			dev_warn(dev, "failed to get passive parent: %d\n", ret);
		goto err;
	}

	priv->devfreq = devm_devfreq_add_device(dev, &priv->profile,
						gov, govdata);
	if (IS_ERR(priv->devfreq)) {
		ret = PTR_ERR(priv->devfreq);
		dev_err(dev, "failed to add devfreq device: %d\n", ret);
		goto err;
	}

	return 0;

err:
	dev_pm_opp_of_remove_table(dev);
	return ret;
}

static const struct of_device_id imx_devfreq_of_match[] = {
	{ .compatible = "fsl,imx8m-noc", },
	{ .compatible = "fsl,imx8m-nic", },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, imx_devfreq_of_match);

static struct platform_driver imx_devfreq_platdrv = {
	.probe		= imx_devfreq_probe,
	.driver = {
		.name	= "imx-devfreq",
		.of_match_table = of_match_ptr(imx_devfreq_of_match),
	},
};
module_platform_driver(imx_devfreq_platdrv);

MODULE_DESCRIPTION("Generic i.MX bus frequency driver");
MODULE_AUTHOR("Leonard Crestez <leonard.crestez@nxp.com>");
MODULE_LICENSE("GPL v2");
