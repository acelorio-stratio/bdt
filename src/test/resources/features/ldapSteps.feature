Feature: LDAP steps test

  Background: Establish connection to LDAP server
    Given I connect to LDAP

  Scenario: Search for a specific user and get some of its attributes
    When I search in LDAP using the filter 'uid=abrookes' and the baseDn 'dc=stratio,dc=com'
    Then The LDAP entry returned in the previous query contains the attribute 'uid' with the value 'abrookes'
    And The LDAP entry returned in the previous query contains the attribute 'sn' with the value 'Anthony'
    And The LDAP entry returned in the previous query contains the attribute 'gidNumber' with the value '101'