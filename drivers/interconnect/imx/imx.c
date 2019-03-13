// SPDX-License-Identifier: GPL-2.0
/*
 * Interconnect framework driver for i.MX SoC
 *
 * Copyright (c) 2019, BayLibre
 * Copyright (c) 2019, NXP
 * Author: Alexandre Bailon <abailon@baylibre.com>
 * Author: Leonard Crestez <leonard.crestez@nxp.com>
 */

#include <linux/devfreq.h>
#include <linux/device.h>
#include <linux/interconnect-provider.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_qos.h>

#include "imx.h"

/* private icc_provider data */
struct imx_icc_provider {
	struct device *dev;
};

/* private icc_node data */
struct imx_icc_node {
	const struct imx_icc_node_desc *desc;
	struct devfreq *devfreq;
	struct dev_pm_qos_request qos_req;
};

static int imx_icc_aggregate(struct icc_node *node, u32 tag,
			     u32 avg_bw, u32 peak_bw,
			     u32 *agg_avg, u32 *agg_peak)
{
	*agg_avg += avg_bw;
	*agg_peak = max(*agg_peak, peak_bw);

	return 0;
}

static struct icc_node *imx_icc_xlate(struct of_phandle_args *spec, void *data)
{
	struct imx_icc_provider *desc = data;
	struct icc_provider *provider = dev_get_drvdata(desc->dev);
	unsigned int id = spec->args[0];
	struct icc_node *node;

	list_for_each_entry(node, &provider->nodes, node_list)
		if (node->id == id)
			return node;

	return ERR_PTR(-EINVAL);
}

static int imx_icc_node_set(struct icc_node *node)
{
	struct device *dev = node->provider->dev;
	struct imx_icc_node *node_data = node->data;
	u64 freq;

	if (!node_data->devfreq)
		return 0;

	freq = (node->avg_bw + node->peak_bw) * node_data->desc->adj->bw_mul;
	do_div(freq, node_data->desc->adj->bw_div);
	dev_dbg(dev, "node %s device %s avg_bw %ukBps peak_bw %ukBps min_freq %llukHz\n",
			node->name, dev_name(node_data->devfreq->dev.parent),
			node->avg_bw, node->peak_bw, freq);

	if (freq > S32_MAX) {
		dev_err(dev, "%s can't request more than S32_MAX freq\n",
				node->name);
		return -ERANGE;
	}

	dev_pm_qos_update_request(&node_data->qos_req, freq);

	return 0;
}

static int imx_icc_set(struct icc_node *src, struct icc_node *dst)
{
	return imx_icc_node_set(dst);
}

static int imx_icc_node_init_devfreq(struct device *dev,
				     struct icc_node *node)
{
	struct imx_icc_node *node_data = node->data;
	struct device_node *dn;
	u32 node_id;
	int ret;

	/* Find nodes based on interconnect-node-id property */
	for_each_node_with_property(dn, "interconnect-node-id") {
		ret = of_property_read_u32(dn, "interconnect-node-id",
					   &node_id);
		if (ret != 0)
			continue;

		if (node_id == node->id) {
			of_node_get(dn);
			break;
		}
	}

	if (!dn)
		return 0;

	dev_info(dev, "node %s[%d] has device node %pOF\n",
			node->name, node->id, dn);
	node_data->devfreq = devfreq_get_devfreq_by_node(dn);
	if (IS_ERR(node_data->devfreq)) {
		of_node_put(dn);
		ret = PTR_ERR(node_data->devfreq);
		dev_err(dev, "failed to fetch devfreq for %s: %d\n",
				node->name, ret);
		return ret;
	}

	of_node_put(dn);

	return dev_pm_qos_add_request(node_data->devfreq->dev.parent,
				      &node_data->qos_req,
				      DEV_PM_QOS_MIN_FREQUENCY, 0);
}

static struct icc_node *imx_icc_node_add(struct icc_provider *provider,
		const struct imx_icc_node_desc *node_desc)
{
	struct imx_icc_provider *provider_data = provider->data;
	struct device *dev = provider_data->dev;
	struct imx_icc_node *node_data;
	struct icc_node *node;
	int ret;

	node = icc_node_create(node_desc->id);
	if (IS_ERR(node)) {
		dev_err(dev, "failed to create node %d\n", node_desc->id);
		return node;
	}

	if (node->data) {
		dev_err(dev, "already created node %s id=%d\n",
				node_desc->name, node_desc->id);
		return ERR_PTR(-EEXIST);
	}

	node_data = devm_kzalloc(dev, sizeof(*node_data), GFP_KERNEL);
	if (!node_data) {
		icc_node_destroy(node->id);
		return ERR_PTR(-ENOMEM);
	}

	node->name = node_desc->name;
	node->data = node_data;
	node_data->desc = node_desc;
	icc_node_add(node, provider);

	if (node_desc->adj) {
		ret = imx_icc_node_init_devfreq(dev, node);
		if (ret < 0) {
			icc_node_del(node);
			icc_node_destroy(node->id);
			return ERR_PTR(ret);
		}
	}

	return node;
}

static void imx_icc_unregister_nodes(struct icc_provider *provider)
{
	struct icc_node *node, *tmp;

	list_for_each_entry_safe(node, tmp, &provider->nodes, node_list) {
		struct imx_icc_node *node_data = node->data;

		icc_node_del(node);
		icc_node_destroy(node->id);
		if (dev_pm_qos_request_active(&node_data->qos_req))
			dev_pm_qos_remove_request(&node_data->qos_req);
	}
}

static int imx_icc_register_nodes(struct icc_provider *provider,
				  const struct imx_icc_node_desc *descs,
				  int count)
{
	int ret;
	int i;

	for (i = 0; i < count; i++) {
		struct icc_node *node;
		const struct imx_icc_node_desc *node_desc = &descs[i];
		size_t j;

		node = imx_icc_node_add(provider, node_desc);
		if (IS_ERR(node)) {
			ret = PTR_ERR(node);
			if (ret != -EPROBE_DEFER)
				dev_err(provider->dev, "failed to add %s: %d\n",
						node_desc->name, ret);
			goto err;
		}

		for (j = 0; j < node_desc->num_links; j++)
			icc_link_create(node, node_desc->links[j]);
	}

	return 0;

err:
	imx_icc_unregister_nodes(provider);

	return ret;
}

int imx_icc_register(struct platform_device *pdev,
		     struct imx_icc_node_desc *nodes, int nodes_count)
{
	struct device *dev = &pdev->dev;
	struct imx_icc_provider *provider_data;
	struct icc_provider *provider;
	int ret;

	provider_data = devm_kzalloc(dev, sizeof(*provider_data), GFP_KERNEL);
	if (!provider_data)
		return -ENOMEM;
	provider_data->dev = dev;

	provider = devm_kzalloc(dev, sizeof(*provider), GFP_KERNEL);
	if (!provider)
		return -ENOMEM;
	provider->set = imx_icc_set;
	provider->aggregate = imx_icc_aggregate;
	provider->xlate = imx_icc_xlate;
	provider->data = provider_data;
	provider->dev = dev->parent;
	platform_set_drvdata(pdev, provider);

	ret = icc_provider_add(provider);
	if (ret) {
		dev_err(dev, "error adding interconnect provider: %d\n", ret);
		return ret;
	}

	ret = imx_icc_register_nodes(provider, nodes, nodes_count);
	if (ret)
		goto provider_del;

	pr_info("registered %s\n", pdev->name);

	return 0;

provider_del:
	icc_provider_del(provider);
	return ret;
}
EXPORT_SYMBOL_GPL(imx_icc_register);

int imx_icc_unregister(struct platform_device *pdev)
{
	struct icc_provider *provider = platform_get_drvdata(pdev);

	icc_provider_del(provider);
	imx_icc_unregister_nodes(provider);

	return 0;
}
EXPORT_SYMBOL_GPL(imx_icc_unregister);
