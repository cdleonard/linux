// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 NXP
 */
#include <kunit/test.h>
#include <linux/pm_qos.h>

static void freq_qos_test_min(struct kunit *test)
{
	struct freq_constraints	qos;
	struct freq_qos_request	req1, req2;
	int ret;

	freq_constraints_init(&qos);
	memset(&req1, 0, sizeof(req1));
	memset(&req2, 0, sizeof(req2));

	ret = freq_qos_add_request(&qos, &req1, FREQ_QOS_MIN, 1000);
	KUNIT_EXPECT_EQ(test, ret, 1);
	ret = freq_qos_add_request(&qos, &req2, FREQ_QOS_MIN, 2000);
	KUNIT_EXPECT_EQ(test, ret, 1);

	KUNIT_EXPECT_EQ(test, freq_qos_read_value(&qos, FREQ_QOS_MIN), 2000);

	freq_qos_remove_request(&req2);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, freq_qos_read_value(&qos, FREQ_QOS_MIN), 1000);

	freq_qos_remove_request(&req1);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, freq_qos_read_value(&qos, FREQ_QOS_MIN),
			FREQ_QOS_MIN_DEFAULT_VALUE);
}

static void freq_qos_test_maxdef(struct kunit *test)
{
	struct freq_constraints	qos;
	struct freq_qos_request	req1, req2;
	int ret;

	freq_constraints_init(&qos);
	memset(&req1, 0, sizeof(req1));
	memset(&req2, 0, sizeof(req2));
	KUNIT_EXPECT_EQ(test, freq_qos_read_value(&qos, FREQ_QOS_MAX),
			FREQ_QOS_MAX_DEFAULT_VALUE);

	ret = freq_qos_add_request(&qos, &req1, FREQ_QOS_MAX,
			FREQ_QOS_MAX_DEFAULT_VALUE);
	KUNIT_EXPECT_EQ(test, ret, 0);
	ret = freq_qos_add_request(&qos, &req2, FREQ_QOS_MAX,
			FREQ_QOS_MAX_DEFAULT_VALUE);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Add max 1000 */
	ret = freq_qos_update_request(&req1, 1000);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, freq_qos_read_value(&qos, FREQ_QOS_MAX), 1000);

	/* Add max 2000, no impact */
	ret = freq_qos_update_request(&req2, 2000);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, freq_qos_read_value(&qos, FREQ_QOS_MAX), 1000);

	/* Remove max 2000, new max 1000 */
	ret = freq_qos_remove_request(&req1);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, freq_qos_read_value(&qos, FREQ_QOS_MAX), 2000);
}

static struct kunit_case pm_qos_test_cases[] = {
	KUNIT_CASE(freq_qos_test_min),
	KUNIT_CASE(freq_qos_test_maxdef),
	{},
};

static struct kunit_suite pm_qos_test_module = {
	.name = "qos-kunit-test",
	.test_cases = pm_qos_test_cases,
};
kunit_test_suite(pm_qos_test_module);
