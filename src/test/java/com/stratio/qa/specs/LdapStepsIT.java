package com.stratio.qa.specs;

import com.stratio.qa.cucumber.testng.CucumberRunner;
import com.stratio.qa.utils.BaseTest;
import cucumber.api.CucumberOptions;
import org.testng.annotations.Test;

@CucumberOptions(format = "json:target/cucumber.json", features = {"src/test/resources/features/ldapSteps.feature"})
public class LdapStepsIT extends BaseTest {

    @Test
    public void ldapStepsTest() throws Exception {
        new CucumberRunner(this.getClass()).runCukes();
    }
}
