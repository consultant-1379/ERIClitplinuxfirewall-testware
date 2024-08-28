"""
COPYRIGHT Ericsson 2019
The copyright to the computer program(s) herein is the property of
Ericsson Inc. The programs may be used and/or copied only with written
permission from Ericsson Inc. or in accordance with the terms and
conditions stipulated in the agreement/contract under which the
program(s) have been supplied.

@since:     Oct 2017
@author:    Laura Forbes
@summary:   TORF-217079
            As a LITP user I want to be able to accept/block
            specific types of ICMPv4 & ICMPv6 packets in my
            firewalls configuration (DTAG Item 12)
"""
from litp_generic_test import GenericTest, attr
import test_constants as const


class Story217079(GenericTest):
    """
        As a LITP user I want to be able to accept/block specific types of
        ICMPv4 & ICMPv6 packets in my firewalls configuration (DTAG Item 12)
    """

    def setUp(self):
        """ Runs before every single test """
        self.dummy_for_pylint_obsoletion = attr()
        super(Story217079, self).setUp()

        self.ms_node = self.get_management_node_filename()
        self.all_nodes = [self.ms_node] + self.get_managed_node_filenames()

        # Firewalls rules path under MS
        self.ms_fw_rules_path = self.find(
            self.ms_node, '/ms', 'collection-of-firewall-rule')[0]

        # Firewalls rules path under deployment
        self.cluster_path = self.find(
            self.ms_node, '/deployments', 'vcs-cluster')[0]
        self.cluster_configs_path = self.find(
            self.ms_node, self.cluster_path, 'collection-of-cluster-config')[0]
        self.cluster_fw_rules_path = self.find(
            self.ms_node, self.cluster_configs_path,
            'collection-of-firewall-rule')[0]

        # Firewalls rules paths under nodes
        self.mn_node_paths = self.find(
            self.ms_node, '/deployments', 'node')
        self.mn_fw_rules_paths = []
        for node in self.mn_node_paths:
            self.mn_fw_rules_paths.append(self.find(
                self.ms_node, node, 'collection-of-firewall-rule')[0])

    def tearDown(self):
        """ Runs after every single test """
        super(Story217079, self).tearDown()

    def _check_iptables(self, rule, present=True, rule_check=None, ip6=False):
        """
        Description:
            Check whether specified iptables rules exist on MS and nodes.
        Args:
            rule (str): Rule-type to check.
        Kwargs:
            present (bool): Whether the rule is
                expected to exist. Default is True.
            rule_check (str): Exact properties of rule to check.
            ip6 (bool): Check ip6tables instead of iptables. Default is False.
        """
        if ip6:
            cmd = "/sbin/ip6tables -L | grep {0}".format(rule)
        else:
            cmd = "/sbin/iptables -L | grep {0}".format(rule)

        for node in self.all_nodes:
            std_out, std_err, rc = self.run_command(node, cmd, su_root=True)
            if present:
                # Assert rule is present
                self.assertEqual(0, rc)
                self.assertEqual([], std_err)
                if rule_check:
                    self.assertTrue(
                        any(rule_check in s for s in std_out),
                        "Expected rule '{0}' not present in {1}.".format(
                            rule_check, cmd.split('/')[-1].split()[0]))
            else:
                # Assert rule is not present
                self.assertEqual([], std_out)
                self.assertEqual(1, rc)

    def create_fw_rule(self, path, props):
        """
        Description:
            Creates a firewall rule on the specified
                path with the given properties.
        Args:
            path (str): LITP path where rule is to be created
            props (str): Properties for firewall rule
        """
        self.execute_cli_create_cmd(self.ms_node, path, "firewall-rule", props)

    #@attr('pre-reg', 'revert', 'story217079', 'story217079_tc07')
    def obsolete_07_p_multiple_icmp_rules(self):
        """
        Obsoleted as functionality moved to test_02_p_create_rules
            in testset_firewall_rule_positive.py

            @#tms_id: torf_217079_tc07
            @#tms_requirements_id: TORF-217079
            @#tms_title: Create multiple icmp rules at MS,
                cluster and node levels for v4 and v6
            @#tms_description: Apply a firewall rule to the LITP model on
                peer nodes with protocol set to icmp and ipv6-icmp,
                on the MS, cluster and node levels
            @#tms_test_steps:
                @step: Create "timestamp-reply" iptables rule on MS level
                @result: Rule created successfully
                @step: Create "timestamp-reply" iptables rule on cluster level
                @result: Rule created successfully
                @step: Create "redirect" ip6tables rule on MS level
                @result: Rule created successfully
                @step: Create "redirect" ip6tables rule on cluster level
                @result: Rule created successfully
                @step: Create "echo-reply" iptables rule on MS level
                @result: Rule created successfully
                @step: Create "echo-reply" iptables rule on cluster level
                @result: Rule created successfully
                @step: Create "echo-reply" ip6tables rule on MS level
                @result: Rule created successfully
                @step: Create "echo-reply" ip6tables rule on cluster level
                @result: Rule created successfully
                @step: Create "echo-request" iptables rule on MS level
                @result: Rule created successfully
                @step: Create "echo-request" iptables rule on cluster level
                @result: Rule created successfully
                @step: Create "echo-request" ip6tables rule on MS level
                @result: Rule created successfully
                @step: Create "echo-request" ip6tables rule on cluster level
                @result: Rule created successfully
                @step: Create and run LITP plan
                @result: Plan runs to completion
                @step: Check iptables and ip6tables on all
                    nodes have been updated with new rules
                @result: New rules added successfully
            @#tms_test_precondition: None
            @#tms_execution_type: Automated
        """
        # Firewall paths for test
        fw_icmps = ['/fw_icmp1', '/fw_icmp2', '/fw_icmp3',
                    '/fw_icmp4', '/fw_icmp5', '/fw_icmp6']

        self.log('info', 'Show current iptables/ip6tables '
                         'rules for MS and peer nodes.')
        show_iptables = "/sbin/iptables -L; /sbin/ip6tables -L"
        for node in self.all_nodes:
            self.log('info', '***** {0} *****'.format(node))
            self.run_command(node, show_iptables, su_root=True)

        # TC1
        self.log('info', '1.1. Ensure "timestamp-reply" is not '
                         'already in iptables on MS or peer nodes.')
        self._check_iptables("timestamp-reply", False)
        self.log('info', '1.2. Create "timestamp-reply" '
                         'iptables rule on MS level.')
        props = 'name="014 icmp" action=drop ' \
                'proto=icmp icmp=14 provider=iptables'
        self.create_fw_rule(self.ms_fw_rules_path + fw_icmps[0], props)
        self.log('info', '1.3. Create "timestamp-reply" '
                         'iptables rule on cluster level.')
        self.create_fw_rule(self.cluster_fw_rules_path + fw_icmps[0], props)

        # TC4
        self.log('info', '2.1. Ensure "redirect" is not already'
                         ' in ip6tables on MS or peer nodes.')
        self._check_iptables("redirect", False, None, True)
        self.log('info', '2.2. Create "redirect" ip6tables rule on MS level.')
        props = 'name="137 icmpv6" action=drop ' \
                'proto=ipv6-icmp icmp=137 provider=ip6tables'
        self.create_fw_rule(self.ms_fw_rules_path + fw_icmps[1], props)
        self.log('info', '2.3. Create "redirect" ip6tables '
                         'rule on cluster level.')
        self.create_fw_rule(self.cluster_fw_rules_path + fw_icmps[1], props)

        # TC3
        self.log('info', '3.1. Ensure "echo-" is not already'
                         ' in iptables on MS or peer nodes.')
        self._check_iptables("echo", False)
        self.log('info', '3.2. Create "echo-reply" iptables rule on MS level.')
        props = 'name="003 icmp" action=accept proto=icmp ' \
                'icmp=echo-reply provider=iptables'
        self.create_fw_rule(self.ms_fw_rules_path + fw_icmps[2], props)
        self.log('info', '3.3. Create "echo-reply" iptables '
                         'rule on cluster level.')
        self.create_fw_rule(self.cluster_fw_rules_path + fw_icmps[2], props)

        # TC6
        self.log('info', '4.1. Ensure "echo-" is not already'
                         ' in ip6tables on MS or peer nodes.')
        self._check_iptables("echo", False, None, True)
        self.log('info', '4.2. Create "echo-reply" ip6tables rule on MS level')
        props = 'name="004 icmpv6" action=accept proto=ipv6-icmp ' \
                'icmp=echo-reply provider=ip6tables'
        self.create_fw_rule(self.ms_fw_rules_path + fw_icmps[3], props)
        self.log('info', '4.3. Create "echo-reply" ip6tables '
                         'rule on cluster level.')
        self.create_fw_rule(self.cluster_fw_rules_path + fw_icmps[3], props)

        # TC2
        self.log('info', '5.1. Create "echo-request" '
                         'iptables rule on MS level.')
        props = 'name="005 icmp" action=accept proto=icmp ' \
                'icmp=echo-request provider=iptables'
        self.create_fw_rule(self.ms_fw_rules_path + fw_icmps[4], props)
        self.log('info', '5.2. Create "echo-request" '
                         'iptables rule on cluster level.')
        for path in self.mn_fw_rules_paths:
            self.create_fw_rule(path + fw_icmps[4], props)

        # TC5
        self.log('info', '6.1. Create "echo-request" '
                         'ip6tables rule on MS level.')
        props = 'name="006 icmpv6" action=accept proto=ipv6-icmp ' \
                'icmp=echo-request provider=ip6tables'
        self.create_fw_rule(self.ms_fw_rules_path + fw_icmps[5], props)
        self.log('info', '6.2. Create "echo-request" ip6tables '
                         'rule on cluster level.')
        for path in self.mn_fw_rules_paths:
            self.create_fw_rule(path + fw_icmps[5], props)

        self.log('info', '7. Create and run a LITP plan.')
        self.execute_cli_createplan_cmd(self.ms_node)
        self.execute_cli_runplan_cmd(self.ms_node)

        self.log('info', '8. Wait for the plan to succeed.')
        self.assertEqual(True, self.wait_for_plan_state(
            self.ms_node, const.PLAN_COMPLETE))

        self.log('info', '9. Check iptables and ip6tables on all '
                         'nodes have been updated successfully.')
        for node in self.all_nodes:
            self.log('info', '***** {0} *****'.format(node))
            self.run_command(node, show_iptables, su_root=True)

            self._check_iptables("timestamp", True,
                                "/* 014 icmp ipv4 */ icmp timestamp-reply")
            self._check_iptables("redirect", True,
                                "/* 137 icmpv6 ipv6 */ ipv6-icmp redirect",
                                True)
            self._check_iptables("echo-reply", True,
                                "/* 003 icmp ipv4 */ icmp echo-reply")
            self._check_iptables("echo-reply", True,
                                "/* 004 icmpv6 ipv6 */ ipv6-icmp echo-reply",
                                True)
            self._check_iptables("echo-request", True,
                                "/* 005 icmp ipv4 */ icmp echo-request")
            self._check_iptables("echo-request", True,
                                "/* 006 icmpv6 ipv6 */ ipv6-icmp echo-request",
                                True)
