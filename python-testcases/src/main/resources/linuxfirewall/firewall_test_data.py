"""
Data file for linuxfirewall tests
"""

############################
# DEFAULT OPEN & CLOSED PORTS #
############################
DEFAULT_MS_IP4_6_PORTS = ["22", "67", "68", "69", "80", "123", "443",
                          "8139", "8140", "9999", "4369", "9100", "9101",
                          "9102", "9103", "9104", "9105", "12987", "61613",
                          "61614"]
DEFAULT_MN_IP4_6_PORTS = ["22", "80", "123", "8139", "8140", "9999", "4369",
                          "9100", "9101", "9102", "9103", "9104", "9105",
                          "12987", "61614"]
DEFAULT_MS_CLOSED_PORTS = ["5672"]
DEFAULT_MN_CLOSED_PORTS = ["5672", "61613"]

###################################
# DATA FOR test_01_p_load_rules_from_XML #
###################################

XML_NODE_RULES = [['INPUT', '10.45.239.85', '10.45.239.87', 'udp',
                                '30000:65000', '078 test20c', 'NEW', 'ACCEPT']]

XML_CLUSTER_RULES_DEFAULT = [['INPUT', '129.167.122.99', '129.167.122.99',
                        'tcp', '1123', '65531', '201 test20', 'NEW', 'ACCEPT']]

XML_CLUSTER_RULES_NAT = [['PREROUTING', '10.45.239.85-10.45.239.87', '162',
                'REDIRECT', '070 test20e', 'udp', '10.45.239.84-10.45.239.85',
                'NEW', '30162']]

############################################################################
# DATA FOR testset_firewall_rule_negative_validation                       #
# This test is a refactoring of the following tests from                   #
#   testset_story2075_2076_2892.py:                                        #
# test_30_p_create_update_remove_duplicate_rule_split_chain                #
# test_31_p_remove_and_create_same_rule                                    #
# test_32_n_remove_rule_from_cluster_and_create_on_node                    #
############################################################################

#Rules 01 and 02 have same sequence number on different chains on MS
# used to check if same sequences clash on same chain and don't clash
# on different chains
#Rules 03 is on cluster level, rule 04 is on node level
# used for checking if rules can be removed and recreated in same plan
#Rule 05 is on cluster level
# used to make sure rule can't be removed from cluster and made on node
# in same plan
RULE_SET = {
'rule 01': {
    'props': 'name="080 in chain" chain=INPUT dport=9999',
    'expected_ipv4_rules': [
        ['-A INPUT', '-p tcp', '--dport 9999',
         '-m comment --comment "080 in chain ipv4"',
         '-m state --state NEW', '-j ACCEPT'],
    ],
    'expected_ipv6_rules': [
        ['-A INPUT', '-p tcp', '--dport 9999',
         '-m comment --comment "080 in chain ipv6"',
         '-m state --state NEW', '-j ACCEPT'],
    ]
},
'rule 02': {
    'props': 'name="080 out chain" chain=OUTPUT sport=9999',
    'expected_ipv4_rules': [
        ['-A OUTPUT', '-p tcp', '--sport 9999',
         '-m comment --comment "1080 out chain ipv4"',
         '-m state --state NEW', '-j ACCEPT']
    ],
    'expected_ipv6_rules': [
        ['-A OUTPUT', '-p tcp', '--sport 9999',
         '-m comment --comment "1080 out chain ipv6"',
         '-m state --state NEW', '-j ACCEPT']
    ]
},
'rule 03': {
    'props': 'name="081 create remove" dport="12321"',
    'expected_ipv4_rules': [
        ['-A INPUT', '-p tcp', '--dport 12321',
         '-m comment --comment "081 create remove ipv4"',
         '-m state --state NEW', '-j ACCEPT'],
        ['-A OUTPUT', '-p tcp', '--dport 12321',
         '-m comment --comment "1081 create remove ipv4"',
         '-m state --state NEW', '-j ACCEPT'],
    ],
    'expected_ipv6_rules': [
        ['-A INPUT', '-p tcp', '--dport 12321',
         '-m comment --comment "081 create remove ipv6"',
         '-m state --state NEW', '-j ACCEPT'],
        ['-A OUTPUT', '-p tcp', '--dport 12321',
         '-m comment --comment "1081 create remove ipv6"',
         '-m state --state NEW', '-j ACCEPT'],
    ]
},
'rule 04': {
    'props': 'name="082 create remove" sport="22345"',
    'expected_ipv4_rules': [
        ['-A INPUT', '-p tcp', '--sport 22345',
         '-m comment --comment "082 create remove ipv4"',
         '-m state --state NEW', '-j ACCEPT'],
        ['-A OUTPUT', '-p tcp', '--sport 22345',
         '-m comment --comment "1082 create remove ipv4"',
         '-m state --state NEW', '-j ACCEPT'],
    ],
    'expected_ipv6_rules': [
        ['-A INPUT', '-p tcp', '--sport 22345',
         '-m comment --comment "082 create remove ipv6"',
         '-m state --state NEW', '-j ACCEPT'],
        ['-A OUTPUT', '-p tcp', '--sport 22345',
         '-m comment --comment "1082 create remove ipv6"',
         '-m state --state NEW', '-j ACCEPT'],
    ]
},
'rule 05': {
    'props': 'name="083 remove create" dport="12321"',
    'expected_ipv4_rules': [
        ['-A INPUT', '-p tcp', '--dport 12321',
         '-m comment --comment "083 remove create ipv4"',
         '-m state --state NEW', '-j ACCEPT'],
        ['-A OUTPUT', '-p tcp', '--dport 12321',
         '-m comment --comment "1083 remove create ipv4"',
         '-m state --state NEW', '-j ACCEPT']
    ],
    'expected_ipv6_rules': [
        ['-A INPUT', '-p tcp', '--dport 12321',
         '-m comment --comment "083 remove create ipv6"',
         '-m state --state NEW', '-j ACCEPT'],
        ['-A OUTPUT', '-p tcp', '--dport 12321',
         '-m comment --comment "1083 remove create ipv6"',
         '-m state --state NEW', '-j ACCEPT']
    ]
}
}

RULE_06 = {
    "props": 'name="083 remove create" dport="12321"',
    "expected_ipv4_rules": [
            ['-A INPUT', '-p tcp', '--dport 12321',
             '-m comment --comment "083 new name ipv4"',
             '-m state --state NEW', '-j ACCEPT'],
            ['-A OUTPUT', '-p tcp', '--dport 12321',
             '-m comment --comment "1083 new name ipv4"',
             '-m state --state NEW', '-j ACCEPT']
    ],
    "expected_ipv6_rules": [
            ['-A INPUT', '-p tcp', '--dport 12321',
             '-m comment --comment "083 new name ipv6"',
             '-m state --state NEW', '-j ACCEPT'],
            ['-A OUTPUT', '-p tcp', '--dport 12321',
             '-m comment --comment "1083 new name ipv6"',
             '-m state --state NEW', '-j ACCEPT']
        ]
}

ERR1 = ("ValidationError    Create plan failed: Position "
       "'80' in the firewall chain 'OUTPUT' is not "
       "unique on node 'ms1'")
ERR2 = ("ValidationError    Create plan failed: Rule name "
       "'083 remove create' is not unique for reused "
       "chain number")

NEW_RULE_01 = {
    'expected_ipv4_rules': [
        ['-A OUTPUT', '-p tcp', '--dport 9999',
         '-m comment --comment "1080 in chain ipv4"',
         '-m state --state NEW', '-j ACCEPT'],
    ],
    'expected_ipv6_rules': [
        ['-A OUTPUT', '-p tcp', '--dport 9999',
         '-m comment --comment "1080 in chain ipv6"',
         '-m state --state NEW', '-j ACCEPT'],
    ]
}

NEW_RULE_02 = {
    'expected_ipv4_rules': [
        ['-A INPUT', '-p tcp', '--sport 9999',
         '-m comment --comment "080 out chain ipv4"',
         '-m state --state NEW', '-j ACCEPT'],
    ],
    'expected_ipv6_rules': [
        ['-A INPUT', '-p tcp', '--sport 9999',
         '-m comment --comment "080 out chain ipv6"',
         '-m state --state NEW', '-j ACCEPT'],
    ]
}

NEW_RULE_03 = {
    'props': 'name="081 create remove" dport="33654"',
    'expected_ipv4_rules': [
        ['-A INPUT', '-p tcp', '--dport 33654',
         '-m comment --comment "081 create remove ipv4"',
         '-m state --state NEW', '-j ACCEPT'],
        ['-A OUTPUT', '-p tcp', '--dport 33654',
         '-m comment --comment "1081 create remove ipv4"',
         '-m state --state NEW', '-j ACCEPT'],
    ],
    'expected_ipv6_rules': [
        ['-A INPUT', '-p tcp', '--dport 33654',
         '-m comment --comment "081 create remove ipv6"',
         '-m state --state NEW', '-j ACCEPT'],
        ['-A OUTPUT', '-p tcp', '--dport 33654',
         '-m comment --comment "1081 create remove ipv6"',
         '-m state --state NEW', '-j ACCEPT'],
    ]
}

NEW_RULE_04 = {
    'props': 'name="082 create remove" sport="33789"',
    'expected_ipv4_rules': [
        ['-A INPUT', '-p tcp', '--sport 33789',
         '-m comment --comment "082 create remove ipv4"',
         '-m state --state NEW', '-j ACCEPT'],
        ['-A OUTPUT', '-p tcp', '--sport 33789',
         '-m comment --comment "1082 create remove ipv4"',
         '-m state --state NEW', '-j ACCEPT'],
    ],
    'expected_ipv6_rules': [
        ['-A INPUT', '-p tcp', '--sport 33789',
         '-m comment --comment "082 create remove ipv6"',
         '-m state --state NEW', '-j ACCEPT'],
        ['-A OUTPUT', '-p tcp', '--sport 33789',
         '-m comment --comment "1082 create remove ipv6"',
         '-m state --state NEW', '-j ACCEPT'],
    ]
}
####################################################
# TEST DATA FOR test_02_p_create_rules and test_03_p_update_remove_rules #
####################################################
# COMMON FIREWALL PROPERTIES #
####################################################

SPORT = ['110', '111', '112', '113']
DPORT = ['9200', '9201', '162']
PROVIDER = ["iptables", "ip6tables"]
ACTION = ["drop", "accept", "reject"]
JUMP = ["LOG", "REDIRECT", "DSCP", "SNAT"]
LOG_LEVEL = ["panic", "alert", "crit", "err", "warn", "warning",
             "notice", "info", "debug"]
STATE = ["RELATED", "ESTABLISHED", "NEW", "INVALID"]
PROTO = ["tcp", "udp", "icmp", "ipv6-icmp"]
CHAIN = ["PREROUTING", "INPUT", "POSTROUTING", "OUTPUT", "FORWARD"]
TABLE = ["filter", "mangle", "nat", "raw"]
IN_OUT_IFACE = ["eth0", "lo", "2", "3"]
ICMP = ["14", "137", "echo-reply", "echo-request", "0", "8"]
ALGO = ["bm", "kmp"]
STRING_PROP = ["DELETE /enm_logs-application-"]

SYSTEM = ["ms", "cluster", "node", "node-config"]


####################################################
# RULES TEST DATA #
####################################################

#### test_01_p_snat_rules_node & test_14_p_firewall_rules_stop_plan ####

SNAT_TCP_PATH_NAME = "fw_snat_tcp_story199859"
SNAT_UDP_PATH_NAME = "fw_snat_udp_story199859"
SNAT_SOURCE = "100.100.100.0/24"
SNAT_DESTINATION = "200.200.200.0/24"
SNAT_TOSOURCE = "200.200.200.130"
SNAT_TOSOURCE_PROP_UPDATE = "200.200.200.160"

#test_01_p_snat_rules_node

FW_SNAT_TCP_MS = dict()
FW_SNAT_TCP_MS["TYPE"] = SYSTEM[0]
FW_SNAT_TCP_MS["PATH_NAME"] = [SNAT_TCP_PATH_NAME]
FW_SNAT_TCP_MS["PROPS"] = [{"provider": PROVIDER[0], "name": "9001 SNAT" \
                           " tcp", "jump": JUMP[3], "chain": CHAIN[2],
                           "source": SNAT_SOURCE, "destination":
                           SNAT_DESTINATION, "proto": PROTO[0],
                           "table": TABLE[2], "tosource": SNAT_TOSOURCE}]
#test_01_p_snat_rules_node

FW_SNAT_TCP_MS_UPDATE = dict()
FW_SNAT_TCP_MS_UPDATE["TYPE"] = SYSTEM[0]
FW_SNAT_TCP_MS_UPDATE["PATH_NAME"] = [SNAT_TCP_PATH_NAME]
FW_SNAT_TCP_MS_UPDATE["PROPS"] = [{"tosource": SNAT_TOSOURCE_PROP_UPDATE}]
FW_SNAT_TCP_MS_UPDATE["DELETE_PROP"] = []

#test_01_p_snat_rules_node
FW_SNAT_TCP_NODE = dict()
FW_SNAT_TCP_NODE["TYPE"] = SYSTEM[2]
FW_SNAT_TCP_NODE["PATH_NAME"] = [SNAT_TCP_PATH_NAME]
FW_SNAT_TCP_NODE["PROPS"] = [{"provider": PROVIDER[0], "name": "9003 SNAT" \
                           " tcp", "jump": JUMP[3], "chain": CHAIN[2],
                           "source": SNAT_SOURCE, "destination":
                           SNAT_DESTINATION, "proto": PROTO[0],
                           "table": TABLE[2], "tosource": SNAT_TOSOURCE}]

#test_01_p_snat_rules_node
FW_SNAT_TCP_NODE_UPDATE = dict()
FW_SNAT_TCP_NODE_UPDATE["TYPE"] = SYSTEM[2]
FW_SNAT_TCP_NODE_UPDATE["PATH_NAME"] = [SNAT_TCP_PATH_NAME]
FW_SNAT_TCP_NODE_UPDATE["PROPS"] = [{"tosource": SNAT_TOSOURCE_PROP_UPDATE}]
FW_SNAT_TCP_NODE_UPDATE["DELETE_PROP"] = []

#test_01_p_snat_rules_node
FW_SNAT_TCP_CLUSTER = dict()
FW_SNAT_TCP_CLUSTER["TYPE"] = SYSTEM[1]
FW_SNAT_TCP_CLUSTER["PATH_NAME"] = [SNAT_TCP_PATH_NAME]
FW_SNAT_TCP_CLUSTER["PROPS"] = [{"provider": PROVIDER[0], "name": \
                                 "9005 SNAT tcp", "jump": JUMP[3],
                                 "chain": CHAIN[2], "source": \
                                 SNAT_SOURCE, "destination":
                                 SNAT_DESTINATION, "proto": PROTO[0],
                                 "table": TABLE[2], "tosource": SNAT_TOSOURCE
                                 }]

#test_01_p_snat_rules_node
FW_SNAT_TCP_CLUSTER_UPDATE = dict()
FW_SNAT_TCP_CLUSTER_UPDATE["TYPE"] = SYSTEM[1]
FW_SNAT_TCP_CLUSTER_UPDATE["PATH_NAME"] = [SNAT_TCP_PATH_NAME]
FW_SNAT_TCP_CLUSTER_UPDATE["PROPS"] = [{"tosource": SNAT_TOSOURCE_PROP_UPDATE}]
FW_SNAT_TCP_CLUSTER_UPDATE["DELETE_PROP"] = []

#test_01_p_snat_rules_node
FW_SNAT_UDP_MS = dict()
FW_SNAT_UDP_MS["TYPE"] = SYSTEM[0]
FW_SNAT_UDP_MS["PATH_NAME"] = [SNAT_UDP_PATH_NAME]
FW_SNAT_UDP_MS["PROPS"] = [{"provider": PROVIDER[0], "name": "9002 SNAT"\
                           " udp", "jump": JUMP[3], "chain": CHAIN[2],
                           "source": SNAT_SOURCE, "destination":
                           SNAT_DESTINATION, "proto": PROTO[1],
                           "table": TABLE[2], "tosource": SNAT_TOSOURCE}]

#test_01_p_snat_rules_node
FW_SNAT_UDP_MS_UPDATE = dict()
FW_SNAT_UDP_MS_UPDATE["TYPE"] = SYSTEM[0]
FW_SNAT_UDP_MS_UPDATE["PATH_NAME"] = [SNAT_UDP_PATH_NAME]
FW_SNAT_UDP_MS_UPDATE["PROPS"] = [{"tosource": SNAT_TOSOURCE_PROP_UPDATE}]
FW_SNAT_UDP_MS_UPDATE["DELETE_PROP"] = []


#test_01_p_snat_rules_node
FW_SNAT_UDP_NODE = dict()
FW_SNAT_UDP_NODE["TYPE"] = SYSTEM[2]
FW_SNAT_UDP_NODE["PATH_NAME"] = [SNAT_UDP_PATH_NAME]
FW_SNAT_UDP_NODE["PROPS"] = [{"provider": PROVIDER[0], "name": "9004 SNAT"\
                           " udp", "jump": JUMP[3], "chain": CHAIN[2],
                           "source": SNAT_SOURCE, "destination":
                           SNAT_DESTINATION, "proto": PROTO[1],
                           "table": TABLE[2], "tosource": SNAT_TOSOURCE}]

#test_01_p_snat_rules_node
FW_SNAT_UDP_NODE_UPDATE = dict()
FW_SNAT_UDP_NODE_UPDATE["TYPE"] = SYSTEM[2]
FW_SNAT_UDP_NODE_UPDATE["PATH_NAME"] = [SNAT_UDP_PATH_NAME]
FW_SNAT_UDP_NODE_UPDATE["PROPS"] = [{"tosource": SNAT_TOSOURCE_PROP_UPDATE}]
FW_SNAT_UDP_NODE_UPDATE["DELETE_PROP"] = []

#test_01_p_snat_rules_node
FW_SNAT_UDP_CLUSTER = dict()
FW_SNAT_UDP_CLUSTER["TYPE"] = SYSTEM[1]
FW_SNAT_UDP_CLUSTER["PATH_NAME"] = [SNAT_UDP_PATH_NAME]
FW_SNAT_UDP_CLUSTER["PROPS"] = [{"provider": PROVIDER[0], "name": \
                                "9006 SNAT udp", "jump": JUMP[3],
                                "chain": CHAIN[2], "source": \
                                SNAT_SOURCE, "destination":
                                SNAT_DESTINATION, "proto": PROTO[1],
                                "table": TABLE[2], "tosource": SNAT_TOSOURCE
                                }]
#test_01_p_snat_rules_node
FW_SNAT_UDP_CLUSTER_UPDATE = dict()
FW_SNAT_UDP_CLUSTER_UPDATE["TYPE"] = SYSTEM[1]
FW_SNAT_UDP_CLUSTER_UPDATE["PATH_NAME"] = [SNAT_UDP_PATH_NAME]
FW_SNAT_UDP_CLUSTER_UPDATE["PROPS"] = [{"tosource": SNAT_TOSOURCE_PROP_UPDATE}]
FW_SNAT_UDP_CLUSTER_UPDATE["DELETE_PROP"] = []


#### test_01_p_create_firewall_rules & test_02_p_update_firewall_rules ####

#test_01_p_create_firewall_rules
CREATE_FW_RULE_CLUSTER = dict()
CREATE_FW_RULE_CLUSTER["TYPE"] = SYSTEM[1]
CREATE_FW_RULE_CLUSTER["PATH_NAME"] = ["214216_test01", "214216_test02",
                                      "214216_test10", "214216_test17A",
                                      "214216_test19", "fw018_rule05",
                                      "214216_test22", "214216_test23",
                                      "214216_test24", "214216_test25"]
CREATE_FW_RULE_CLUSTER["PROPS"] = [{"name": "21421601 test01", "sport":
                                    SPORT[0], "provider": PROVIDER[0],
                                    "action": ACTION[0]},
                                    {"name": "21421602 test02",
                                   "sport": SPORT[0], "provider":
                                    PROVIDER[1], "action": ACTION[0]},
                                    {"name": "21421610 test10", "dport":
                                     "9200,9201", "sport": SPORT[1] + "," \
                                     + SPORT[0], "provider": PROVIDER[1],
                                     "action": ACTION[0]},
                                    {"name":
                                     "214216171 test17A", "sport": SPORT[0],
                                     "dport": DPORT[0], "provider":
                                      PROVIDER[0], "action": ACTION[0]},
                                    {"name":
                                     "214216 test19", "sport": SPORT[0] + ","
                                     + SPORT[1],
                                    "dport": DPORT[0] + "," + DPORT[1],
                                    "provider":
                                     PROVIDER[0],
                                     "action": ACTION[0]},
                                     {"name": "222 test", "jump": JUMP[0],
                                      "log_level": LOG_LEVEL[5],
                                      "log_prefix":"valid",
                                      "provider": PROVIDER[0]},
                                      {"name": "231 test", "sport": SPORT[2] +\
                                      "," + SPORT[0], "provider": PROVIDER[1],
                                      "action": ACTION[1]},
                                      {"name": "743 test", "dport": DPORT[0] +\
                                       "," + DPORT[1], "action": ACTION[2]},
                                      {"name": "432 test", "sport": SPORT[2] +\
                                       "," + SPORT[1], "action": ACTION[0]},
                                      {"name": "875 test", "sport": SPORT[2] +\
                                        "," + SPORT[0], "dport": DPORT[2]}]
#test_02_p_update_firewall_rules
CREATE_FW_RULE_CLUSTER_UPDATE = dict()
CREATE_FW_RULE_CLUSTER_UPDATE["TYPE"] = SYSTEM[1]
CREATE_FW_RULE_CLUSTER_UPDATE["PATH_NAME"] = ["214216_test01", "214216_test02",
                                              "214216_test10",
                                              "214216_test17A",
                                              "214216_test19",
                                              "fw018_rule05",
                                              "fw018_rule05",
                                              "214216_test23",
                                              "214216_test24",
                                              "214216_test25"]
CREATE_FW_RULE_CLUSTER_UPDATE["PROPS"] = [{"name": "21421609 test09", "sport":
                                           SPORT[0] + "," + SPORT[1], "dport":
                                           DPORT[0] + "," + DPORT[1],
                                           "provider": PROVIDER[1], "chain":
                                           CHAIN[1]},
                                          {"name": "214216033 test02", "sport":
                                           SPORT[0] + "," + SPORT[1] + "," +
                                           SPORT[2]},
                                          {"name":"21421606 test06", "sport":
                                           SPORT[0]},
                                          {"name": "21421614 test17A",
                                           "dport": DPORT[0] + "," + DPORT[1],
                                           "sport": SPORT[1] + "," + SPORT[0]},
                                          {"name":
                                           "214216032 test19", "sport":
                                           SPORT[1] + "," + SPORT[0], "dport":
                                           DPORT[1]},
                                           {"proto": PROTO[1], "log_prefix":
                                            "valid_testing"},
                                           {"log_level": "log_level",
                                            "provider": "provider"},
                                            {"dport": DPORT[1]},
                                            {"sport": SPORT[2]},
                                            {"sport": SPORT[3], "dport":
                                             DPORT[2]}]
CREATE_FW_RULE_CLUSTER_UPDATE["DELETE_PROP"] = [6]


#test_01_p_create_firewall_rules
CREATE_FW_RULE_NODE = dict()
CREATE_FW_RULE_NODE["TYPE"] = SYSTEM[2]
CREATE_FW_RULE_NODE["PATH_NAME"] = ["214216_test04"]
CREATE_FW_RULE_NODE["PROPS"] = [{"name": "21421604 test04", "dport": DPORT[0],
                                 "sport": SPORT[2], "provider": PROVIDER[0],
                                 "action": ACTION[0], "iniface":
                                 IN_OUT_IFACE[1]}]

#test_02_p_update_firewall_rules
CREATE_FW_RULE_NODE_UPDATE = dict()
CREATE_FW_RULE_NODE_UPDATE["TYPE"] = SYSTEM[2]
CREATE_FW_RULE_NODE_UPDATE["PATH_NAME"] = ["214216_test04"]
CREATE_FW_RULE_NODE_UPDATE["PROPS"] = [{"name": "21421612 test04", "sport":
                                        SPORT[2] + "," + SPORT[3], "dport":
                                        DPORT[0] + "," + DPORT[1],
                                        "provider": PROVIDER[1],
                                        "iniface": IN_OUT_IFACE[3]}]
CREATE_FW_RULE_NODE_UPDATE["DELETE_PROP"] = []


#test_01_p_create_firewall_rule_positive_validation
CREATE_RULE_POS_VAL_CLUSTER = dict()
CREATE_RULE_POS_VAL_CLUSTER["TYPE"] = SYSTEM[1]
CREATE_RULE_POS_VAL_CLUSTER["PATH_NAME"] = ["fw_story2075_tc01_1",
                                            "fw_story2075_tc01_2",
                                            "fw_story2075_tc01_3",
                                            "fw_story2075_tc01_4",
                                            "fw_story2075_tc01_6",
                                            "fw_story2075_tc01_11",
                                            "fw_story2075_tc01_12",
                                            "fw_story2075_tc01_13",
                                            "fw_story2075_tc01_14",
                                            "fw_story2075_tc01_44",
                                            "fw_story2075_tc01_45",
                                            "fw_story2075_tc01_46",
                                            "fw_story2075_tc01_47",
                                            "fw_story2075_tc01_48",
                                            "fw_story2075_tc01_49"]
CREATE_RULE_POS_VAL_CLUSTER["PROPS"] = [{"name": "5", "jump": JUMP[0],
                                         "log_prefix": "test", "log_level":
                                         LOG_LEVEL[1], "state": STATE[0] +
                                         "," + STATE[1], "proto": PROTO[0],
                                         "chain": CHAIN[0], "table": TABLE[3]},
                                        {"name": "0", "jump": JUMP[0],
                                         "log_level": LOG_LEVEL[2],
                                         "chain": CHAIN[1]},
                                        {"name": "01234567890", "jump":
                                         JUMP[0],
                                        "log_level": LOG_LEVEL[7],
                                         "chain": CHAIN[2],
                                         "proto": PROTO[1], "dport": DPORT[2],
                                         "destination":
                                         "2001:db8:0:1:5054:ff:fe01:2346",
                                         "provider": PROVIDER[1],
                                         "table": TABLE[1]},
                                        {"name": "555555", "jump": JUMP[0],
                                         "log_level": LOG_LEVEL[3],
                                         "chain": CHAIN[2], "proto": PROTO[1],
                                         "dport":
                                         "22,80,111,443,3000,25151,9999",
                                         "source": "10.10.10.131",
                                         "provider": PROVIDER[0],
                                         "table": TABLE[2]},
                                        {"name": " 01899 NAME", "jump":
                                          JUMP[0],
                                         "log_level": LOG_LEVEL[8],
                                         "chain": CHAIN[0], "proto": PROTO[1],
                                         "dport": DPORT[2], "destination":
                                         "2001:db8:0:1:5054:ff:fe01:2345",
                                         "provider": PROVIDER[1], "table":
                                         TABLE[1]},
                                        {"name": "75 xxxxxxxxxxxxxxxxxxxxxx"\
                                        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\
                                        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\
                                        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\
                                        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\
                                        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\
                                        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\
                                        "xxxxxxx",
                                        "proto": PROTO[0], "limit": "5/sec",
                                        "sport": "1234-65535", "state":
                                        STATE[1] + "," + STATE[0], "source":
                                        "129.167.122.89",
                                        "provider": PROVIDER[0],
                                        "chain": CHAIN[3]},
                                        {"name": "45", "proto": PROTO[3],
                                         "limit": "56/day", "source":
                                         "fe80:0000:0000:0000:2002:b3ff:"\
                                         "fe1e:8329", "provider": PROVIDER[1],
                                         "chain": CHAIN[4], "destination":
                                         "fe80::a00:27ff:febc:c8e1/64",
                                         "jump": JUMP[0], "log_level":
                                         LOG_LEVEL[6]},
                                        {"name": "460", "proto": PROTO[0],
                                         "action": ACTION[1], "sport": "1",
                                         "dport":
                                         "12345,2,3,4,5,6,7,8,9,10,11"\
                                         ",12,13,14,15", "state": STATE[2] +
                                         "," + STATE[1] + "," + STATE[0],
                                         "provider": PROVIDER[0],
                                         "source": "10.10.1.0/24", "iniface":
                                         IN_OUT_IFACE[0], "outiface":
                                         IN_OUT_IFACE[0], "table": TABLE[0],
                                         "destination":
                                         "10.10.10.15-10.10.10.20",
                                         "chain": CHAIN[4]},
                                        {"name": "47 test", "proto": PROTO[1],
                                         "sport":
                                         "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
                                         "dport": "1234-65535", "state":
                                         STATE[3], "source":
                                         "10.10.10.5-10.10.10.10",
                                         "destination": "129.167.122.99",
                                         "provider": PROVIDER[0],
                                         "iniface": IN_OUT_IFACE[1],
                                         "outiface":  IN_OUT_IFACE[1],
                                         "chain": CHAIN[0],
                                         "jump": JUMP[1], "table": TABLE[2],
                                         "toports": "30162"},
                                        {"name": "7 3test", "sport": "22",
                                        "table": TABLE[1], "jump": JUMP[2],
                                        "setdscp": "0x10", "chain": CHAIN[3],
                                        "proto": PROTO[0], "outiface":
                                         IN_OUT_IFACE[2], "provider":
                                         PROVIDER[0]},
                                        {"name": "7 3test", "sport": "22",
                                        "table": TABLE[1], "jump": JUMP[2],
                                        "setdscp": "0x10", "chain": CHAIN[2],
                                        "proto": PROTO[0], "outiface":
                                         IN_OUT_IFACE[2], "provider":
                                         PROVIDER[0]},
                                        {"name": "01234", "state": STATE[2],
                                         "source":
                                         "fe80::a00:27ff:febc:c8e1/64",
                                         "provider": PROVIDER[1]},
                                         {"name": "012345", "state": STATE[2],
                                         "source":
                                         "fe80::a00:27ff:febc:c8e1/64",
                                         "provider": PROVIDER[1]},
                                         {"name": "7751 test",
                                          "proto": PROTO[2],
                                          "icmp": ICMP[5],
                                          "provider": PROVIDER[0],
                                          "chain": CHAIN[1]},
                                          {"name": "142 test", "proto":
                                           PROTO[2],
                                           "icmp": ICMP[4], "provider":
                                           PROVIDER[0]}]

CREATE_RULE_POS_VAL_CLUSTER_UPDATE = dict()
CREATE_RULE_POS_VAL_CLUSTER_UPDATE["TYPE"] = SYSTEM[1]
CREATE_RULE_POS_VAL_CLUSTER_UPDATE["PATH_NAME"] = ["fw_story2075_tc01_44",
                                                  "fw_story2075_tc01_44"]
CREATE_RULE_POS_VAL_CLUSTER_UPDATE["PROPS"] = [{"provider": "provider"},
                                        {"setdscp": "0x20",
                                         "outiface": IN_OUT_IFACE[1]}]
CREATE_RULE_POS_VAL_CLUSTER_UPDATE["DELETE_PROP"] = [0]

#test_33_p_create_firewall_rules_with_string_algo & test_34_p_update_
#firewall_rules_with_string_algo

#test_33_p_create_firewall_rules_with_string_algo
CREATE_RULE_STR_ALGO_CLUSTER = dict()
CREATE_RULE_STR_ALGO_CLUSTER["TYPE"] = SYSTEM[1]
CREATE_RULE_STR_ALGO_CLUSTER["PATH_NAME"] = ["fw_story200553_n_rule_1",
                                             "fw_story200553_n_rule_3",
                                             "fw_story200553_n_rule_4",
                                             "fw_story200553_n_rule_5",
                                             "fw_story200553_n_rule_6"]

CREATE_RULE_STR_ALGO_CLUSTER["PROPS"] = [{"name": "026 test1", "dport":
                                          DPORT[0], "action": ACTION[1],
                                          "provider": PROVIDER[0],
                                          "source": "129.167.122.99",
                                          "algo": ALGO[0], "string":
                                          STRING_PROP[0]},
                                         {"name": "032 test7", "dport":
                                          DPORT[0], "proto": PROTO[0],
                                          "action": ACTION[0],
                                          "provider": PROVIDER[0],
                                          "source": "!192.168.0.0/20",
                                          "algo": ALGO[1], "string":
                                          STRING_PROP[0]},
                                         {"name": "034 test8", "dport":
                                          DPORT[0], "proto": PROTO[0],
                                          "action": ACTION[2],
                                          "provider": PROVIDER[0],
                                          "source": "192.168.0.0/20",
                                          "algo": ALGO[1], "string":
                                          STRING_PROP[0]},
                                          {"name": "038 test10",
                                          "proto": PROTO[0],
                                          "action": ACTION[0],
                                          "provider": PROVIDER[0],
                                          "source": "! 192.168.0.0/20",
                                          "state": "none", "sport": SPORT[0],
                                          "dport": DPORT[0]},
                                          {"name": "040 test11", "string":
                                           STRING_PROP[0], "algo": ALGO[1]}]


#test_33_p_create_firewall_rules_with_string_algo
CREATE_RULE_STR_ALGO_NODE = dict()
CREATE_RULE_STR_ALGO_NODE["TYPE"] = SYSTEM[2]
CREATE_RULE_STR_ALGO_NODE["PATH_NAME"] = ["fw_story200553_n_rule_1",
                                          "fw_story200553_n_rule_2",
                                          "fw_story200553_n_rule_3",
                                          "fw_story200553_n_rule_4",
                                          "fw_story200553_n_rule_5",
                                          "fw_story200553_n_rule_6"]
CREATE_RULE_STR_ALGO_NODE["PROPS"] = [{"name": "027 testnode", "dport":
                                       DPORT[0],
                                       "proto": PROTO[0], "action": ACTION[1],
                                       "provider": PROVIDER[0], "source":
                                       "129.167.122.90", "algo": ALGO[1],
                                       "string": STRING_PROP[0]},
                                      {"name": "029 testnode2", "dport":
                                        DPORT[0], "proto": PROTO[0],
                                        "action": ACTION[0],
                                       "provider": PROVIDER[0], "source":
                                       "!192.167.0.0/20", "algo": ALGO[1],
                                       "string": STRING_PROP[0]},
                                      {"name": "072 test6", "dport": DPORT[0],
                                       "proto": PROTO[0], "action": ACTION[2],
                                       "provider": PROVIDER[0], "source":
                                       "!192.166.0.0/20", "algo": ALGO[1],
                                       "string": STRING_PROP[0]},
                                      {"name": "086 testnode3", "sport":
                                        SPORT[0], "proto": PROTO[0],
                                        "state": "none",
                                       "provider": PROVIDER[0], "source":
                                       "192.168.0.0/20"},
                                      {"name": "054 test5", "dport": DPORT[0],
                                       "proto": PROTO[0], "action": ACTION[1],
                                       "provider": PROVIDER[0], "source":
                                       "192.168.0.0/20", "algo": ALGO[1],
                                       "string": STRING_PROP[0]},
                                       {"name": "081 test", "dport": DPORT[0],
                                        "provider": PROVIDER[0], "source":
                                        "192.112.1.30"}]

#test_34_p_update_firewall_rules_with_string_algo
CREATE_RULE_STR_ALGO_NODE_UPDATE = dict()
CREATE_RULE_STR_ALGO_NODE_UPDATE["TYPE"] = SYSTEM[2]
CREATE_RULE_STR_ALGO_NODE_UPDATE["PATH_NAME"] = ["fw_story200553_n_rule_1",
                                                 "fw_story200553_n_rule_2",
                                                 "fw_story200553_n_rule_3",
                                                 "fw_story200553_n_rule_4",
                                                 "fw_story200553_n_rule_5",
                                                 "fw_story200553_n_rule_6"]
CREATE_RULE_STR_ALGO_NODE_UPDATE["PROPS"] = [{"algo": ALGO[0], "action":
                                              ACTION[2]},
                                             {"string": "new test string"},
                                             {"action": ACTION[0]},
                                             {"source": "! 192.168.0.0/20"},
                                             {"action": "action", "algo":
                                              "algo", "string": "string"},
                                             {"source": "! 192.168.0.95"}]
CREATE_RULE_STR_ALGO_NODE_UPDATE["DELETE_PROP"] = [4]


#test_34_p_update_firewall_rules_with_string_algo
CREATE_RULE_STR_ALGO_CLUSTER_UPDATE = dict()
CREATE_RULE_STR_ALGO_CLUSTER_UPDATE["TYPE"] = SYSTEM[1]
CREATE_RULE_STR_ALGO_CLUSTER_UPDATE["PATH_NAME"] = ["fw_story200553_n_rule_1",
                                                    "fw_story200553_n_rule_3",
                                                    "fw_story200553_n_rule_4",
                                                    "fw_story200553_n_rule_4",
                                                    "fw_story200553_n_rule_5"]

CREATE_RULE_STR_ALGO_CLUSTER_UPDATE["PROPS"] = [{"algo": ALGO[1], "source":
                                                 "!129.167.122.91"},
                                                {"action": ACTION[2],
                                                 "string": "new test string"},
                                                {"action": "action", "algo":
                                                 "algo", "string": "string"},
                                                {"source": "! 192.168.0.0/20"},
                                                 {"action": ACTION[2]}]
CREATE_RULE_STR_ALGO_CLUSTER_UPDATE["DELETE_PROP"] = [2]


#### test_07_p_multiple_icmp_rules ####

#test_07_p_multiple_icmp_rules
CREATE_ICMP_RULE_MS = dict()
CREATE_ICMP_RULE_MS["TYPE"] = SYSTEM[0]
CREATE_ICMP_RULE_MS["PATH_NAME"] = ["fw_icmp1", "fw_icmp2", "fw_icmp3",
                                    "fw_icmp4", "fw_icmp5", "fw_icmp6"]
CREATE_ICMP_RULE_MS["PROPS"] = [{"name": "014 icmp", "action": ACTION[0],
                                      "proto": PROTO[2], "icmp": ICMP[0],
                                      "provider": PROVIDER[0]},
                                     {"name": "137 icmpv6", "action":
                                     ACTION[0], "proto": PROTO[3],
                                     "icmp": ICMP[1],
                                      "provider": PROVIDER[1]},
                                     {"name": "003 icmp", "action": ACTION[1],
                                      "proto": PROTO[2], "icmp": ICMP[2],
                                      "provider": PROVIDER[0]},
                                     {"name": "004 icmpv6", "action":
                                      ACTION[1], "proto": PROTO[3],
                                      "icmp": ICMP[2],
                                      "provider": PROVIDER[1]},
                                     {"name": "005 icmp", "action": ACTION[1],
                                      "proto": PROTO[2], "icmp": ICMP[3],
                                      "provider": PROVIDER[0]},
                                      {"name": "006 icmpv6", "action":
                                      ACTION[1],
                                      "proto": PROTO[3], "icmp": ICMP[3],
                                      "provider": PROVIDER[1]}]

#test_07_p_multiple_icmp_rules
CREATE_ICMP_RULE_CLUSTER = dict()
CREATE_ICMP_RULE_CLUSTER["TYPE"] = SYSTEM[1]
CREATE_ICMP_RULE_CLUSTER["PATH_NAME"] = ["fw_icmp1", "fw_icmp2", "fw_icmp3",
                                         "fw_icmp4"]
CREATE_ICMP_RULE_CLUSTER["PROPS"] = [{"name": "014 icmp", "action": ACTION[0],
                                      "proto": PROTO[2], "icmp": ICMP[0],
                                      "provider": PROVIDER[0]},
                                     {"name": "137 icmpv6", "action":
                                     ACTION[0], "proto": PROTO[3],
                                     "icmp": ICMP[1],
                                      "provider": PROVIDER[1]},
                                     {"name": "003 icmp", "action": ACTION[1],
                                      "proto": PROTO[2], "icmp": ICMP[2],
                                      "provider": PROVIDER[0]},
                                     {"name": "004 icmpv6", "action":
                                      ACTION[1], "proto": PROTO[3],
                                      "icmp": ICMP[2],
                                      "provider": PROVIDER[1]}]

#test_07_p_multiple_icmp_rules
CREATE_ICMP_RULE_NODE = dict()
CREATE_ICMP_RULE_NODE["TYPE"] = SYSTEM[2]
CREATE_ICMP_RULE_NODE["PATH_NAME"] = ["fw_icmp5", "fw_icmp6"]
CREATE_ICMP_RULE_NODE["PROPS"] = [{"name": "005 icmp", "action": ACTION[1],
                                   "proto": PROTO[2], "icmp": ICMP[3],
                                   "provider": PROVIDER[0]},
                                  {"name": "006 icmpv6", "action":ACTION[1],
                                   "proto": PROTO[3], "icmp": ICMP[3],
                                    "provider": PROVIDER[1]}]

#test_08_p_create_firewall_rule_disable

FIRST_UPDATE_FW_RULE_DISABLE_NODE = dict()
FIRST_UPDATE_FW_RULE_DISABLE_NODE["TYPE"] = SYSTEM[3]
FIRST_UPDATE_FW_RULE_DISABLE_NODE["PATH_NAME"] = ["fw_config_init"]
FIRST_UPDATE_FW_RULE_DISABLE_NODE["PROPS"] = [{"drop_all": "false"}]
FIRST_UPDATE_FW_RULE_DISABLE_NODE["DELETE_PROP"] = []

FIRST_UPDATE_FW_RULE_DISABLE_NODE["EXPECTED_RULE"] = \
                                 [['INPUT', '999 drop all']]

SECOND_UPDATE_FW_RULE_DISABLE_NODE = dict()
SECOND_UPDATE_FW_RULE_DISABLE_NODE["TYPE"] = SYSTEM[3]
SECOND_UPDATE_FW_RULE_DISABLE_NODE["PATH_NAME"] = ["fw_config_init"]
SECOND_UPDATE_FW_RULE_DISABLE_NODE["PROPS"] = [{"drop_all" : "true"}]
SECOND_UPDATE_FW_RULE_DISABLE_NODE["DELETE_PROP"] = []

#test_21_p_create_firewall_rules_purges_manually_added_rules

MANUAL_RULE_IPV4 = [['INPUT', 'DROP', '207.52.75.3']]
MANUAL_RULE_IPV6 = [['INPUT', 'DROP', '1:2:3:4:5:6:7:cafb']]

MANUAL_RULE_01 = ' -A INPUT -s 207.52.75.3 -j DROP'
MANUAL_RULE_02 = ' -A INPUT -s 1:2:3:4:5:6:7:cafb -j DROP'

####################################################
# LISTS OF RULES TO BE ADDED/UPDATED #
####################################################

CLUSTER_RULES_LIST = [FW_SNAT_TCP_CLUSTER, FW_SNAT_UDP_CLUSTER,
                     CREATE_FW_RULE_CLUSTER, CREATE_RULE_POS_VAL_CLUSTER,
                     CREATE_RULE_STR_ALGO_CLUSTER, CREATE_ICMP_RULE_CLUSTER]

NODE_MS_RULES_LIST = [FW_SNAT_TCP_MS, FW_SNAT_UDP_MS, FW_SNAT_TCP_NODE,
                      FW_SNAT_UDP_NODE, CREATE_FW_RULE_NODE,
                      CREATE_RULE_STR_ALGO_NODE, CREATE_ICMP_RULE_MS,
                      CREATE_ICMP_RULE_NODE]

UPDATE_FW_RULES_LIST = [FW_SNAT_TCP_MS_UPDATE, FW_SNAT_UDP_MS_UPDATE,
                        FW_SNAT_TCP_NODE_UPDATE, FW_SNAT_UDP_NODE_UPDATE,
                        FW_SNAT_TCP_CLUSTER_UPDATE,
                        FW_SNAT_UDP_CLUSTER_UPDATE,
                        CREATE_FW_RULE_CLUSTER_UPDATE,
                        CREATE_FW_RULE_NODE_UPDATE,
                        CREATE_RULE_POS_VAL_CLUSTER_UPDATE,
                        CREATE_RULE_STR_ALGO_CLUSTER_UPDATE,
                        CREATE_RULE_STR_ALGO_NODE_UPDATE]


####################################################
# EXPECTED RULES #
####################################################

RULES_MS = dict()
RULES_NODE = dict()

RULES_MS = \
{'filter': {'iptables': [['DROP', '14', '014 icmp', 'icmp'],
                        ['ACCEPT', '0', '003 icmp', 'icmp'],
                        ['ACCEPT', '8', '005 icmp', 'icmp']],
           'ip6tables': [['DROP', '137', '137 icmpv6', 'ipv6-icmp'],
                        ['ACCEPT', '0', '004 icmpv6', 'ipv6-icmp'],
                        ['ACCEPT', '8', '006 icmpv6', 'ipv6-icmp']]},

  'raw': {'iptables': [], 'ip6tables': []},

  'mangle': {'iptables': [], 'ip6tables': []},

  'nat': {'iptables': [['SNAT', '100.100.100.0/24', '200.200.200.130',
                         '9001 SNAT tcp', 'POSTROUTING', 'tcp',
                         '200.200.200.0/24'],
                         ['SNAT', '100.100.100.0/24', '200.200.200.130',
                          '9002 SNAT udp', 'POSTROUTING', 'udp',
                          '200.200.200.0/24']],
          'ip6tables': []}}

RULES_NODE = \
{'filter': {'iptables': [['1038 test10', '9200', 'tcp', 'DROP',
                         '192.168.0.0/20', '!', '110'],
                        ['081 test', '9200', "192.112.1.30"],
                        ['040 test11', 'kmp', 'DELETE /enm_logs-application-'],
                        ['DROP', '110', '21421601 test01'],
                        ['7751 test', '8', 'icmp', 'INPUT'],
                        ['1142 test', 'icmp', '0'],
                        ['1222 test', 'valid', 'LOG'],
                        ['9200', 'DROP', '110', '214216171 test17A'],
                        ['9200,9201', 'DROP', '110,111', 'multiport',
                         '214216 test19'],
                        ['9200', 'DROP', '112', '21421604 test04'],
                        ['LOG', '2', '000', 'INPUT', '0'],
                        ['129.167.122.89/32', 'RELATED,ESTABLISHED', '5/sec',
                        '1075 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'\
                        'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'\
                        'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'\
                        'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'\
                        'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'OUTPUT',
                        'tcp', '1234:65535'], ['FORWARD', 'ACCEPT', '1',
                        '2460', 'tcp', '10.10.10.15-10.10.10.20',
                        '10.10.1.0/24',
                        'NEW,RELATED,ESTABLISHED',
                        '12345,2,3,4,5,6,7,8,9,10,11,12,13,14,15'],
                        ['1026 test1', '129.167.122.99/32', 'ACCEPT',
                        'bm', '9200', 'DELETE /enm_logs-application-'],
                        ['DROP', 'kmp', '1032 test7', 'tcp', '9200',
                        'DELETE /enm_logs-application-', '192.168.0.0/20', '!']
                        , ['REJECT', 'kmp', '034 test8', 'tcp', '9200',
                        'DELETE /enm_logs-application-', '192.168.0.0/20']
                        , ['ACCEPT', 'kmp', '027 testnode', 'tcp', '9200',
                        'DELETE /enm_logs-application-', '129.167.122.90/32'],
                         ['DROP', 'kmp', '029 testnode2', 'tcp', '9200',
                         'DELETE /enm_logs-application-',
                         '192.167.0.0/20', '!']
                         , ['REJECT', 'kmp', '072 test6', 'tcp', '9200',
                         'DELETE /enm_logs-application-',
                         '192.166.0.0/20', '!'],
                         ['086 testnode3', 'tcp', '192.168.0.0/20', '110'],
                         ['ACCEPT', 'kmp', '054 test5', 'tcp', '9200',
                          'DELETE /enm_logs-application-', '192.168.0.0/20']
                          , ['DROP', '14', '014 icmp', 'icmp'],
                          ['ACCEPT', '0', '003 icmp', 'icmp'],
                          ['ACCEPT', '8', '005 icmp', 'icmp'],
                          ['432 test', 'DROP', '112,111', 'multiport'],
                          ['743 test', '9200,9201', 'REJECT', 'multiport'],
                          ['875 test', '162', '112,110', 'multiport']],

            'ip6tables': [['DROP', '110', '21421602 test02'],
                                       ['9200,9201', 'DROP', '21421610 test10',
                                        '111,110', 'multiport']
                                       , ['LOG',
                                        'fe80::2002:b3ff:fe1e:8329/128',
                                        'fe80::/64', '56/day', '2045',
                                        'FORWARD', 'ipv6-icmp', '5'],
                                       ['DROP', '137', '137 icmpv6',
                                        'ipv6-icmp'],
                                       ['ACCEPT', '0', '004 icmpv6',
                                        'ipv6-icmp'],
                                       ['ACCEPT', '8', '006 icmpv6',
                                        'ipv6-icmp'],
                                       ['11234', 'NEW',
                                        'fe80::/64'],
                                       ['112345', 'NEW',
                                        'fe80::/64'],
                                        ['231 test', '112,110', 'ACCEPT',
                                         'multiport']]},

  'raw': {'iptables': [['LOG', 'RELATED,ESTABLISHED', 'test', '1', '005',
                        'PREROUTING', 'tcp']],
          'ip6tables': []},

  'mangle': {'iptables': [['1007 3test', 'OUTPUT', 'tcp', '0x10', 'DSCP',
                            '22', '2'], ['007 3test', 'POSTROUTING', 'tcp',
                            '0x10', 'DSCP', '22', '2']],

             'ip6tables': [['LOG', '6', '1234567890', 'POSTROUTING', 'udp',
                             '162', '2001:db8:0:1:5054:ff:fe01:2346/128'],
                            ['LOG', '7', '1899 NAME', 'PREROUTING', 'udp',
                             '162', '2001:db8:0:1:5054:ff:fe01:2345/128']]},

  'nat': {'iptables': [['SNAT', '100.100.100.0/24', '200.200.200.130',
                         '9003 SNAT tcp', 'POSTROUTING', 'tcp',
                         '200.200.200.0/24'],
                        ['SNAT', '100.100.100.0/24', '200.200.200.130',
                          '9004 SNAT udp', 'POSTROUTING', 'udp',
                          '200.200.200.0/24'],
                        ['SNAT', '100.100.100.0/24', '200.200.200.130',
                         '9005 SNAT tcp', 'POSTROUTING', 'tcp',
                         '200.200.200.0/24'],
                        ['SNAT', '100.100.100.0/24', '200.200.200.130',
                         '9006 SNAT udp', 'POSTROUTING', 'udp',
                         '200.200.200.0/24'],
                        ['LOG', '10.10.10.131/32', '3', '555555',
                         'POSTROUTING', 'udp',
                         '22,80,111,443,3000,25151,9999'],
                        ['PREROUTING', 'REDIRECT', '30162',
                         '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15', '047 test',
                         'udp', '129.167.122.99/32', '10.10.10.5-10.10.10.10',
                         'INVALID', '1234:65535']],

          'ip6tables': []}}

UPDATED_RULES_MS = \
{'filter': {'iptables': [['DROP', '14', '014 icmp', 'icmp'],
                        ['ACCEPT', '0', '003 icmp', 'icmp'],
                        ['ACCEPT', '8', '005 icmp', 'icmp']],
           'ip6tables': [['DROP', '137', '137 icmpv6', 'ipv6-icmp'],
                        ['ACCEPT', '0', '004 icmpv6', 'ipv6-icmp'],
                        ['ACCEPT', '8', '006 icmpv6', 'ipv6-icmp']]},

  'raw': {'iptables': [], 'ip6tables' : []},

  'mangle': {'iptables': [], 'ip6tables' : []},

  'nat': {'iptables': [['SNAT', '100.100.100.0/24', SNAT_TOSOURCE_PROP_UPDATE,
                         '9001 SNAT tcp', 'POSTROUTING', 'tcp',
                         '200.200.200.0/24'],
                         ['SNAT', '100.100.100.0/24', SNAT_TOSOURCE_PROP_UPDATE
                         , '9002 SNAT udp', 'POSTROUTING', 'udp',
                          '200.200.200.0/24']],
          'ip6tables': []}}

UPDATED_RULES_NODE = \
{'filter': {'iptables': [[DPORT[0] + "," + DPORT[1], '111,110',
                          'DROP', '110', '21421614 test17A', 'multiport'],
                        ['081 test', DPORT[0], "!", "192.168.0.95"],
                        ['1038 test10', '9200', 'tcp', 'REJECT',
                        '192.168.0.0/20', '!'],
                        ['040 test11', 'kmp', 'DELETE /enm_logs-application-'],
                        [DPORT[1], 'DROP', SPORT[1] + "," + SPORT[0],
                         '214216032 test19', 'multiport'],
                        ['1222 test', 'valid_testing', 'udp', 'LOG'],
                        ['1142 test', 'icmp', '0'],
                        ['LOG', '2', '000', 'INPUT'],
                        ['129.167.122.89/32', 'RELATED,ESTABLISHED', '5/sec',
                        '1075 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'\
                        'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'\
                        'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'\
                        'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'\
                        'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'OUTPUT',
                        'tcp', '1234:65535'], ['FORWARD', 'ACCEPT', '1',
                        '2460', 'tcp', '10.10.10.15-10.10.10.20',
                        '10.10.1.0/24',
                        'NEW,RELATED,ESTABLISHED',
                        '12345,2,3,4,5,6,7,8,9,10,11,12,13,14,15'],
                        ['1026 test1', '!', '129.167.122.91/32', 'ACCEPT',
                         'kmp', '9200', 'DELETE /enm_logs-application-',
                         '!'],
                        ['REJECT', 'kmp', '1032 test7', 'tcp', '9200',
                        'new test string', '192.168.0.0/20', '!'],
                        ['034 test8', 'tcp', '9200',
                         '192.168.0.0/20'],
                        ['REJECT', ALGO[0], '027 testnode', 'tcp', '9200',
                        'DELETE /enm_logs-application-', '129.167.122.90/32'],
                        ['DROP', 'kmp', '029 testnode2', 'tcp', '9200',
                         'new test string', '192.167.0.0/20', '!'],
                        ['DROP', 'kmp', '072 test6', 'tcp', '9200',
                         'DELETE /enm_logs-application-',
                         '192.166.0.0/20', '!'],
                        ['086 testnode3', 'tcp', '192.168.0.0/20', '110',
                         '!'],
                        ['054 test5', 'tcp', '9200',
                         '192.168.0.0/20'],
                        ['DROP', '14', '014 icmp', 'icmp'],
                        ['ACCEPT', '0', '003 icmp', 'icmp'],
                        ['ACCEPT', '8', '005 icmp', 'icmp'],
                        ['743 test', '9201', 'REJECT'],
                        ['432 test', 'DROP', '112'],
                        ['875 test', '113', '162']],

            'ip6tables': [['DROP', SPORT[0] + "," + SPORT[1] + "," + SPORT[2],
                           '214216033 test02', 'multiport'],
                          ['9200,9201', 'DROP', '21421606 test06', 'multiport',
                           SPORT[0]],
                          ['LOG', 'fe80::2002:b3ff:fe1e:8329/128',
                           'fe80::/64', '56/day', '2045',
                           'FORWARD', 'ipv6-icmp', '5'],
                          ['DROP', '137', '137 icmpv6', 'ipv6-icmp'],
                          ['ACCEPT', '0', '004 icmpv6', 'ipv6-icmp'],
                          ['ACCEPT', '8', '006 icmpv6', 'ipv6-icmp'],
                          ['DROP', SPORT[0] + "," + SPORT[1], '21421609 test09'
                           , DPORT[0] + "," + DPORT[1], 'multiport'],
                          [DPORT[0] + "," + DPORT[1], 'DROP', SPORT[2] + "," +\
                           SPORT[3], '21421612 test04', 'multiport'],
                           ['11234', 'NEW', 'fe80::/64'],
                           ['112345', 'NEW', 'fe80::/64'],
                           ['231 test', '112,110', 'ACCEPT',
                                         'multiport']]},

  'raw': {'iptables': [['LOG', 'RELATED,ESTABLISHED', 'test', '1', '005',
                        'PREROUTING', 'tcp']],
          'ip6tables': []},

  'mangle': {'iptables': [['1007 3test', 'OUTPUT', 'tcp', '0x20', 'DSCP',
                            '22', 'lo'], ['007 3test', 'POSTROUTING', 'tcp',
                            '0x10', 'DSCP', '22', '2']],

             'ip6tables': [['LOG', '6', '1234567890', 'POSTROUTING', 'udp',
                             '162', '2001:db8:0:1:5054:ff:fe01:2346/128'],
                            ['LOG', '7', '1899 NAME', 'PREROUTING', 'udp',
                             '162', '2001:db8:0:1:5054:ff:fe01:2345/128']]},

  'nat': {'iptables': [['SNAT', '100.100.100.0/24', SNAT_TOSOURCE_PROP_UPDATE,
                         '9003 SNAT tcp', 'POSTROUTING', 'tcp',
                         '200.200.200.0/24'],
                        ['SNAT', '100.100.100.0/24', SNAT_TOSOURCE_PROP_UPDATE,
                          '9004 SNAT udp', 'POSTROUTING', 'udp',
                          '200.200.200.0/24'],
                        ['SNAT', '100.100.100.0/24', SNAT_TOSOURCE_PROP_UPDATE,
                         '9005 SNAT tcp', 'POSTROUTING', 'tcp',
                         '200.200.200.0/24'],
                        ['SNAT', '100.100.100.0/24', SNAT_TOSOURCE_PROP_UPDATE,
                         '9006 SNAT udp', 'POSTROUTING', 'udp',
                         '200.200.200.0/24'],
                        ['LOG', '10.10.10.131/32', '3', '555555',
                         'POSTROUTING', 'udp',
                         '22,80,111,443,3000,25151,9999'],
                        ['PREROUTING', 'REDIRECT', '30162',
                         '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15', '047 test',
                         'udp', '129.167.122.99/32', '10.10.10.5-10.10.10.10',
                         'INVALID', '1234:65535']],

          'ip6tables': []}}
