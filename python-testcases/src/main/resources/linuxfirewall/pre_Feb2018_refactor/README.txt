List of obsolete testcases

================================================================================
Obsoleted test case:
testset_story2075_2076_2892.test_06_p_create_firewall_rule_no_provider_specified

    LITPCDS-12819
    This testcase is covered by case 2.01 of
    testset_story2075_2076_2892.test_01_p_create_firewall_rule_positive_validation

    """
    Description:
    Create firewall rules with no provider specified and test that
    the rule is added to both the iptables and ip6tables

    Actions:
    1. find firewall-cluster-config
    2. Create a cluster level firewall rule
    3. Create plan
    4. Run plan
    5. Check iptables and ip6tables contain correct rules

    Result:
    Correct firewall rules present
    """

================================================================================
Obsoleted test case:
testset_story2075_2076_2892.test_07_p_create_firewall_rule_no_chain_specified

    LITPCDS-12819
    This testcase is covered by case 2.01 of
    testset_story2075_2076_2892.test_01_p_create_firewall_rule_positive_validation

    """
    Description:
    Create a firewall rule with no chain specified and
    verify rule is added to the INPUT and OUTPUT chains

    Actions:
    1. Find firewall-cluster-config
    2. Create a cluster level firewall rule with
       no chain specified
    3. Create plan
    4. Run plan
    5. Check rule has been added to the INPUT and OUTPUT chains

    Result:
    Correct firewall rules present
    """

================================================================================
Obsoleted test case:
testset_story2075_2076_2892.test_09_p_create_firewall_rule_DSCP

    LITPCDS-12819
    This test is covered by case 2.43 of
    testset_story2075_2076_2892.test_01_p_create_firewall_rule_positive_validation

    """
    Description:
    Verify DSCP is supported

    Actions:
    1. Find firewall-cluster-config
    2. Define cluster level firewall rule
    3. Create plan
    4. Run plan
    5. Check DSCP rule is added
    6. Remove firewall-cluster-config and
       cluster level firewall rule
    7. Create plan
    8. Run plan
    9. Check DSCP rule has been removed

    Result:
    Correct firewall rules present on each node
    """

================================================================================
Obsoleted test case:
testset_story2075_2076_2892.test_10_p_create_update_firewall_rule_NAT

    LITPCDS-12819
    This test is covered by case 2.42 of
    testset_story2075_2076_2892.test_01_p_create_firewall_rule_positive_validation

    """
    Description:
    Verify NAT is supported

    Actions:
    1. Find firewall-cluster-config
    2. Define cluster level firewall rule
    3. Create plan
    4. Run plan
    5. Check NAT rule has been added
    6. Update toports value
    7. Create plan
    8. Run plan
    9. Check iptables contain correct rules

    Result:
    Correct firewall rules present on each node
    """

================================================================================
Obsoleted test case:
testset_story2075_2076_2892.test_11_p_create_firewall_rule_logging_and_log_limits

    LITPCDS-12819
    This testcase is covered by case 2.12 of
    testset_story2075_2076_2892.test_01_p_create_firewall_rule_positive_validation

    """
    Description:
    Verify logging and log limits are supported

    Actions:
    1. Find firewall-cluster-config
    2. Define cluster level firewall rule
    3. Create plan
    4. Run plan
    5. Check iptables contain correct rules

    Result:
    Correct firewall rules present on each node
    """

================================================================================
Obsoleted test case:
testset_story2075_2076_2892.test_12_p_create_firewall_rule_range

    LITPCDS-12819
    This testcase is covered by case 2.17a of
    testset_story2075_2076_2892..test_01_p_create_firewall_rule_positive_validation

    """
    Description:
    Verify when a range of ip addresses is specified for either the
    source or destination properties, src-range and dest-range
    are in the rule in the iptable

    Actions:
    1. Find firewall-cluster-config
    2. Define cluster level firewall rule with Destination port property
       as a range
    3. Define cluster level firewall rule with source property as a range
       of ip addresses
    4. Define cluster level firewall rule with destination property
       as a range of ip addresses
    5. Create plan
    6. Run plan
    7. Check iptables contain src-range and dst-range when a range of
       ip addresses are specified for source and destination properties
    Result:
    Correct firewall rules present on each node
    """

================================================================================
Obsoleted test case:
testset_story2075_2076_2892.test_15_p_firewall_rules_check_default_properties

    LITPCDS-12819
    This test is covered by several cases of
    testset_story2075_2076_2892..test_01_p_create_firewall_rule_positive_validation

    """
    Description:
    Check that default properties are shown after creating
    firewall rule

    Actions:
    1. Find firewall-cluster-config
    2. Define cluster level firewall rule
    3. Check that default properties are present
       and contain default values

    Result:
    defualt properties are present
    and contain default values
    """

================================================================================
Obsoleted test case:
testset_story2075_2076_2892.test_27_p_create_firewall_rule_forward_prerouting_postrouting

    LITPCDS-12819
    These cases are covered by cases 2.46, 2.47, 2.48, 2.49, 2.50, 2.51 of
    testset_story2075_2076_2892..test_01_p_create_firewall_rule_positive_validation

    """
    Description:
    Verify the plugin functionality as per LITP-9807, that
    iptables and ip6tables contain the firewall rules created
    for the following chain types: FORWARD, PREROUTING and POSTROUTING

    Actions:
    1. Find firewall cluster config already in model
    2. Configure firewall rules
    2a.Create FORWARD chain rule for iptables and ip6tables
    2b.Create PREROUTING chain rule for iptables and ip6tables
    2c.Create POSTROUTING chain rule for iptables and ip6tables
    3. Create plan
    4. Run plan
    5. Wait for plan to complete successfully
    6. Check iptables and ip6tables content to ensure that rules were
       created successfully

    Results:
    Chain type rules have been created successfully and are
    present in both iptables and ip6tables
    """

================================================================================
Obsoleted test case:
testset_story2075_2076_2892.test_03_p_create_firewall_rules_purges_manually_added_rules

Description:
    Test that manually created firewall rules are removed when new rules
    are created in LITP model

    Actions:
    Test that if rules are manually added to the iptables and no rules are
    defined in the litp model, then when rules are defined in litp model,
    these manually added rules are removed and only those defined by LITP
    are present

    1. Add data manually to the iptables
    2. Find firewall-cluster-config
    3. Create firewall rule
    4. Create plan
    5. Run plan
    6. Check iptables contain correct rule

Replaced by:
testset_story2075_2076_2892.test_21_p_create_firewall_rules_purges_manually_added_rules

Gerrit link:
    https://gerrit.ericsson.se/#/c/1296788/

==============================================================================
Obsoleted test case:
testset_story2075_2076_2892.test_29_p_create_and_remove_rules

Description:
    LITPCDS-13399
    Verify that creating and removing firewall rule from
    firewall-node-config results in a successful plan and the rule being
    removed from iptables and ip6tables

    Actions:
        1. Create firewall rule where proto=all
        2. Create and run the plan
        3. Check the rule is in both iptables
        4. Remove the rule
        5. Create and run the plan
        6. Check the rule is not in both iptables

Replaced by:
testset_story2075_2076_2892.test_01_p_create_firewall_rule_positive_validation
This test now include deplyment and removal of all rules created hence it
covers the specific case address this test.

Gerrit link:
    https://gerrit.ericsson.se/#/c/1296788/

