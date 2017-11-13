Feature: LDAP steps test

  Background: Establish connection to LDAP server
    Given I connect to LDAP

  Scenario: Search for a specific user and get some of its attributes
    When I search in LDAP using the filter 'uid=abrookes' and the baseDn 'dc=stratio,dc=com'
    Then the LDAP entry contains the attribute 'uid' with the value 'abrookes'
    And the LDAP entry contains the attribute 'sn' with the value 'Anthony'
    And the LDAP entry contains the attribute 'gidNumber' with the value '101'

  Scenario: Test if multiple scenarios can be run sequentially
    When I search in LDAP using the filter 'uid=abrookes' and the baseDn 'dc=stratio,dc=com'
    Then the LDAP entry contains the attribute 'uid' with the value 'abrookes'

  Scenario: Test if an attribute which has more than one value is correctly found
    When I search in LDAP using the filter 'cn=Developers' and the baseDn 'dc=stratio,dc=com'
    Then the LDAP entry contains the attribute 'memberUid' with the value 'uid=adoucet,ou=People,dc=stratio,dc=com'
    And the LDAP entry contains the attribute 'memberUid' with the value 'uid=irossi,ou=People,dc=stratio,dc=com'