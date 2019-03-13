// SPDX-License-Identifier: GPL-2.0
/*
 * Interconnect framework driver for i.MX SoC
 *
 * Copyright (c) 2019, BayLibre
 * Copyright (c) 2019, NXP
 * Author: Alexandre Bailon <abailon@baylibre.com>
 * Author: Leonard Crestez <leonard.crestez@nxp.com>
 */

#include <linux/device.h>
#include <linux/interconnect-provider.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_qos.h>

#include "imx.h"

/* private icc_node data */
struct imx_icc_node {
	const struct imx_icc_node_desc *desc;
	struct device *qos_dev;
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

static int imx_icc_node_set(struct icc_node *node)
{
	struct device *dev = node->provider->dev;
	struct imx_icc_node *node_data = node->data;
	u64 freq;

	if (!node_data->qos_dev)
		return 0;

	freq = (node->avg_bw + node->peak_bw) * node_data->desc->adj->bw_mul;
	do_div(freq, node_data->desc->adj->bw_div);
	dev_dbg(dev, "node %s device %s avg_bw %ukBps peak_bw %ukBps min_freq %llukHz\n",
			node->name, dev_name(node_data->qos_dev),
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

/* imx_icc_node_destroy() - Destroy an imx icc_node, including private data */
static void imx_icc_node_destroy(struct icc_node *node)
{
	struct imx_icc_node *node_data = node->data;

	if (dev_pm_qos_request_active(&node_data->qos_req))
		dev_pm_qos_remove_request(&node_data->qos_req);
	put_device(node_data->qos_dev);
	icc_node_del(node);
	icc_node_destroy(node->id);
}

static int imx_icc_node_init_qos(struct icc_provider *provider,
				 struct icc_node *node)
{
	struct imx_icc_node *node_data = node->data;
	struct device *dev = provider->dev;
	struct device_node *dn = NULL;
	struct platform_device *pdev;
	int i, count;
	u32 node_id;
	int ret;

	count = of_property_count_u32_elems(dev->of_node,
					    "fsl,scalable-node-ids");
	if (count < 0) {
		dev_err(dev, "Failed to parse fsl,scalable-node-ids: %d\n",
			count);
		return count;
	}

	for (i = 0; i < count; i++) {
		ret = of_property_read_u32_index(dev->of_node,
						 "fsl,scalable-node-ids",
						 i, &node_id);

		if (ret < 0) {
			dev_err(dev, "Failed to parse fsl,scalable-node-ids[%d]: %d\n",
				i, ret);
			return ret;
		}
		if (node_id != node->id)
			continue;

		dn = of_parse_phandle(dev->of_node, "fsl,scalable-nodes", i);
		if (IS_ERR(dn)) {
			dev_err(dev, "Failed to parse fsl,scalable-nodes[%d]: %ld\n",
				i, PTR_ERR(dn));
			return PTR_ERR(dn);
		}
		break;
	}

	/* Allow scaling to be disabled on a per-node basis */
	if (!dn || !of_device_is_available(dn))
		return 0;

	pdev = of_find_device_by_node(dn);
	of_node_put(dn);
	if (!pdev) {
		dev_warn(dev, "node %s[%d] missing device for %pOF\n",
				node->name, node->id, dn);
		return -EPROBE_DEFER;
	}

	node_data->qos_dev = &pdev->dev;
	dev_info(dev, "node %s[%d] has device node %pOF\n",
		 node->name, node->id, dn);
	return dev_pm_qos_add_request(node_data->qos_dev,
				      &node_data->qos_req,
				      DEV_PM_QOS_MIN_FREQUENCY, 0);
}

static struct icc_node *imx_icc_node_add(
		struct icc_provider *provider,
		const struct imx_icc_node_desc *node_desc)
{
	struct device *dev = provider->dev;
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
		ret = imx_icc_node_init_qos(provider, node);
		if (ret < 0) {
			imx_icc_node_destroy(node);
			return ERR_PTR(ret);
		}
	}

	return node;
}

static void imx_icc_unregister_nodes(struct icc_provider *provider)
{
	struct icc_node *node, *tmp;

	list_for_each_entry_safe(node, tmp, &provider->nodes, node_list)
		imx_icc_node_destroy(node);
}

static int imx_icc_register_nodes(struct icc_provider *provider,
				  const struct imx_icc_node_desc *descs,
				  int count)
{
	struct icc_onecell_data *provider_data = provider->data;
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
		provider_data->nodes[node->id] = node;

		for (j = 0; j < node_desc->num_links; j++) {
			ret = icc_link_create(node, node_desc->links[j]);
			if (ret) {
				dev_err(provider->dev, "failed to link node %d to %d: %d\n",
					node->id, node_desc->links[j], ret);
				goto err;
			}
		}
	}

	return 0;

err:
	imx_icc_unregister_nodes(provider);

	return ret;
}

static int get_max_node_id(struct imx_icc_node_desc *nodes, int nodes_count)
{
	int i, ret = 0;

	for (i = 0; i < nodes_count; ++i)
		if (nodes[i].id > ret)
			ret = nodes[i].id;

	return ret;
}

int imx_icc_register(struct platform_device *pdev,
		     struct imx_icc_node_desc *nodes, int nodes_count)
{
	struct device *dev = &pdev->dev;
	struct icc_onecell_data *data;
	struct icc_provider *provider;
	int max_node_id;
	int ret;

	/* icc_onecell_data is indexed by node_id, unlike nodes param */
	max_node_id = get_max_node_id(nodes, nodes_count);
	data = devm_kzalloc(dev, struct_size(data, nodes, max_node_id),
			    GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	data->num_nodes = max_node_id;

	provider = devm_kzalloc(dev, sizeof(*provider), GFP_KERNEL);
	if (!provider)
		return -ENOMEM;
	provider->set = imx_icc_set;
	provider->aggregate = imx_icc_aggregate;
	provider->xlate = of_icc_xlate_onecell;
	provider->data = data;
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
