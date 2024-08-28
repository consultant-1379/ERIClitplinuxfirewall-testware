"""
COPYRIGHT Ericsson 2019
The copyright to the computer program(s) herein is the property of
Ericsson Inc. The programs may be used and/or copied only with written
permission from Ericsson Inc. or in accordance with the terms and
conditions stipulated in the agreement/contract under which the
program(s) have been supplied.

@since:     May 2014, refactored Dec 2015, Apr 2016, Jan 2018
@author:    Priyanka/Maria; Maurizio, Terry; Alan Conroy
@summary:   TORF-106903
                As a LITP developer, I do not want any UT or AT in plugins
                to be dependent on undefined internal Model Manager logic.
                Converted existing ATs (created with stories LITPCDS-2075 and
                LITPCDS-2076) into ITs.
            LITPCDS-2075
                As a LITP User, I want to create a list of IPv4 or IPv6
                firewall rules that can be applied to any node, so that
                I can benefit from the increased security
            LITPCDS-2076
                As a LITP User, I want to remove/update extra firewall rules to
                an already applied configuration, so that I can enhance or
                modify my firewall configuration
"""
import test_constants
import firewall_test_data as data
from litp_generic_test import GenericTest, attr


class DuplicateValidation(GenericTest):
    """
    As a LITP User, I want to create,remove and update a list of IPv4 or
    IPv6 firewall rules that can be applied to any node,
    so that I can benefit from the increased security
    """

    def setUp(self):
        """
        Runs before every single test
        """
        super(DuplicateValidation, self).setUp()
        self.ms_node = self.get_management_node_filename()
        self.mn1, self.mn2 = self.get_managed_node_filenames()[:2]

        self.ms_fw_conf_url = self.find(self.ms_node, '/ms',
                                        'firewall-node-config',
                                        assert_not_empty=False)[0]

        self.cl_fw_conf_url = self.find(self.ms_node, '/deployments',
                                        'firewall-cluster-config',
                                        assert_not_empty=False)[0]

        self.node_fw_conf_url = self.find(self.ms_node, '/deployments',
                                          'firewall-node-config',
                                          assert_not_empty=False)[0]

    def tearDown(self):
        """
        Runs after every single test
        """
        super(DuplicateValidation, self).tearDown()

    def _check_all_expected_rules_are_applied(self, rule_set):
        """
        Description:
            Checks that nodes have expected firewall rules, as
            defined in the supplied dictionary
        Args:
            rule_set (dict): Expected firewall rules
        """
        for rule in rule_set.itervalues():
            for node in rule['nodes']:
                self.check_iptables(node, rule['expected_ipv4_rules'])
                self.check_iptables(node, rule['expected_ipv6_rules'],
                                    ipv6=True)

    @attr('all', 'revert', 'story106903', 'story106903_tc30')
    def test_01_n_duplicate_validation(self):
        """
        @tms_id: torf_106903_tc30
        @tms_requirements_id: TORF-106903
        @tms_title: Duplicate Firewall Validation
        @tms_description: Verify that a user can create rules with same chain
            number and different name provided they apply to different chains,
            can remove and create same rule in one single plan and cannot
            remove a firewall rule at cluster level and create same rule at
            node level in one single plan.
        @tms_test_steps:
            @step: Create rules to be used in test
            @result: Rules created in model successfully
            @step: Run plan and check iptables
            @result: Plan is successful and new rules are in iptables
            @step: Update rule 01 to cause a duplicate error
            @result: Rule updated
            @step: Remove rules 03, 04, 05
            @result: Rules marked ForRemoval successfully
            @step: Recreate rule 05
            @result: Rule 05 recreated
            @step: Run plan expecting it to fail
            @result: Plan fails with expected errors
            @step: Update rule 02 to remove duplicate error
            @result: Rule updated successfully
            @step: Recreate rules 03 and 04
            @result: Rules created successfully
            @step: Update rule 05 to have different name
            @result: Rule created successfully
            @step: Run plan and check iptables
            @result: Plan runs successfully and expected rules are in iptables
        @tms_test_precondition: N/A
        @tms_execution_type: Automated
        """
        tc_id = '106903_tc30'
        ms_node = [self.ms_node]
        mn_nodes = [self.mn1, self.mn2]

        self.log('info', '1. Create fw rules that will be used for the test.')
        rule_set = data.RULE_SET

        rule_set['rule 01']['url'] = '{0}/rules/fw_{1}_01'.format(
                                                        self.ms_fw_conf_url,
                                                        tc_id)
        rule_set['rule 01']['nodes'] = ms_node

        rule_set['rule 02']['url'] = '{0}/rules/fw_{1}_02'.format(
                                                        self.ms_fw_conf_url,
                                                        tc_id)
        rule_set['rule 02']['nodes'] = ms_node

        # Rule 03 and 04 both have their rule urls ending in 03
        # This is intentional as one is at cluster level and one at node level
        rule_set['rule 03']['url'] = '{0}/rules/fw_{1}_03'.format(
                                                    self.cl_fw_conf_url, tc_id)
        rule_set['rule 03']['nodes'] = mn_nodes

        rule_set['rule 04']['url'] = '{0}/rules/fw_{1}_03'.format(
                                                self.node_fw_conf_url,
                                                tc_id)
        rule_set['rule 04']['nodes'] = [self.mn1]

        rule_set['rule 05']['url'] = '{0}/rules/fw_{1}_05'.format(
                                                    self.cl_fw_conf_url, tc_id)
        rule_set['rule 05']['nodes'] = mn_nodes

        for rule in rule_set:
            self.execute_cli_create_cmd(
                self.ms_node, rule_set[rule]['url'],
                'firewall-rule', rule_set[rule]['props'])

        self.log('info', '2. Deploy new firewall items by running a plan.')
        self.run_and_check_plan(
            self.ms_node, expected_plan_state=test_constants.PLAN_COMPLETE,
            plan_timeout_mins=10)

        self.log('info', '3. Check that the correct rules '
                         'have been added to firewalls.')
        self._check_all_expected_rules_are_applied(rule_set)

        self.log('info', '4. Delete property chain of rule 01 to '
                         'cause a duplicate rule error with rule 02.')
        # This causes a duplicate rule error as a rule with no chain
        # property is applied to both input and output chains
        self.execute_cli_update_cmd(self.ms_node,
            rule_set['rule 01']['url'], props='chain', action_del=True)

        rule_set['rule 01']['expected_ipv4_rules'] = \
            data.NEW_RULE_01['expected_ipv4_rules']
        rule_set['rule 01']['expected_ipv6_rules'] = \
            data.NEW_RULE_01['expected_ipv6_rules']

        self.log('info', '5. Mark rules 03, 04 and 05 as ForRemoval.')
        self.execute_cli_remove_cmd(self.ms_node, rule_set['rule 03']['url'])
        self.execute_cli_remove_cmd(self.ms_node, rule_set['rule 04']['url'])
        self.execute_cli_remove_cmd(self.ms_node, rule_set['rule 05']['url'])

        self.log('info', '6. Recreate rule 05 at node level.')
        #Rule 06 made so 05 can retain old url and
        # 06 can define new expected rules
        #Expected IP rules account for name update after failed create_plan
        rule_set['rule 06'] = data.RULE_06
        rule_set['rule 06']["url"] = '{0}/rules/fw_{1}_05'.format(
                                                    self.node_fw_conf_url,
                                                    tc_id)
        rule_set['rule 06']["nodes"] = [self.mn1]

        self.execute_cli_create_cmd(
            self.ms_node, rule_set['rule 06']['url'],
            'firewall-rule', rule_set['rule 06']['props'])

        self.log('info', '7. Attempt to create plan and expect it to fail.')
        _, stderr, _ = self.execute_cli_createplan_cmd(
            self.ms_node, expect_positive=False)

        expected_errors = [
            {
                'url': rule_set['rule 01']['url'],
                'msg': data.ERR1
            },
            {
                'url': rule_set['rule 02']['url'],
                'msg': data.ERR1
            },
            {
                'url': rule_set['rule 05']['url'],
                'msg': data.ERR2
            },
            {
                'url': rule_set['rule 06']['url'],
                'msg': data.ERR2
            }
        ]

        # Remove rule 05 as it is no longer needed and is replaced by rule 06
        rule_set.pop('rule 05')

        missing, extra = self.check_cli_errors(expected_errors, stderr)
        self.assertEqual([], missing,
                         '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
        self.assertEqual([], extra,
                         '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

        self.log('info', '8. Update property chain on rule 01 and 02 so '
                         'that the duplicate property chain is removed.')
        self.execute_cli_update_cmd(
            self.ms_node, rule_set['rule 01']['url'], props='chain=OUTPUT')
        self.execute_cli_update_cmd(
            self.ms_node, rule_set['rule 02']['url'], props='chain=INPUT')

        rule_set['rule 02']['expected_ipv4_rules'] = \
            data.NEW_RULE_02['expected_ipv4_rules']
        rule_set['rule 02']['expected_ipv6_rules'] = \
            data.NEW_RULE_02['expected_ipv6_rules']

        self.log('info', '9. Re-create the rules 03 and 04.')
        # Same rules with different ports
        rule_set['rule 03']['props'] = data.NEW_RULE_03['props']
        rule_set['rule 03']['expected_ipv4_rules'] = \
            data.NEW_RULE_03['expected_ipv4_rules']
        rule_set['rule 03']['expected_ipv6_rules'] = \
            data.NEW_RULE_03['expected_ipv6_rules']

        self.execute_cli_create_cmd(
            self.ms_node, rule_set['rule 03']['url'],
            'firewall-rule', rule_set['rule 03']['props'])

        rule_set['rule 04']['props'] = data.NEW_RULE_04['props']
        rule_set['rule 04']['expected_ipv4_rules'] = \
                                    data.NEW_RULE_04['expected_ipv4_rules']
        rule_set['rule 04']['expected_ipv6_rules'] = \
                                    data.NEW_RULE_04['expected_ipv6_rules']

        self.execute_cli_create_cmd(
            self.ms_node, rule_set['rule 04']['url'],
            'firewall-rule', rule_set['rule 04']['props'])

        self.log('info', '10. Update name of rule 06 to be created at '
                         'node level so that it does not conflict '
                         'with name of rule 05')
        rule_set['rule 06']['props'] = 'name="083 new name"'
        self.execute_cli_update_cmd(self.ms_node,
                                    url=rule_set['rule 06']['url'],
                                    props=rule_set['rule 06']['props'])

        self.log('info', '11. Verify that plan can be '
                         'created and run successfully.')
        self.run_and_check_plan(
            self.ms_node, expected_plan_state=test_constants.PLAN_COMPLETE,
            plan_timeout_mins=10)

        self.log('info', '12. Check that the correct rules are in firewalls.')
        self._check_all_expected_rules_are_applied(rule_set)
