package com.stratio.tests.utils;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.stratio.gosec.api.Systems;
import com.stratio.gosec.api.policy.PolicyService;
import com.stratio.gosec.dyplon.model.Acl;
import com.stratio.gosec.dyplon.model.Action$;
import com.stratio.gosec.dyplon.model.Identities;
import com.stratio.gosec.dyplon.model.Permission$;
import com.stratio.gosec.dyplon.model.Policy;
import com.stratio.gosec.dyplon.model.Resource;
import com.typesafe.config.Config;

import scala.Option;
import scala.Some;
import scala.collection.JavaConversions;
import scala.collection.immutable.Seq;

public class HDFSUtils {

    private final Logger logger = LoggerFactory.getLogger("com.stratio.tests.utils.HDFSUtils");
    private PolicyService policyService = Systems.PolicySystem$.MODULE$.policyService();
    private final String rootPolicyName = "AutoTestPolicy";
    private final String rootPolicyDesc = "Automatic Test Policy";
    private String coreSitePath;
    private String hdfsSitePath;

    private String operationResult = "";

    private Seq<String> instances;
    private Seq<String> services;
    private Option<Identities> opIds;

    private Set<String> createdFiles = new HashSet<>();

    private String username;
    private String realm;
    private String pathKeytab;
    private FileSystem fs;

    private Config gosecConfig;

    public HDFSUtils() {

        this.username = System.getProperty("KERBEROS_HDFS_USER", "testUser");
        this.realm = System.getProperty("KERBEROS_HDFS_REALM", "LABS.STRATIO.COM");
        this.pathKeytab = System.getProperty("KERBEROS_HDFS_KEYTAB", "/tmp/krb.keytab");
        this.coreSitePath = System.getProperty("CORE_SITE_PATH", "/tmp/core-site.xml");
        this.hdfsSitePath = System.getProperty("HDFS_SITE_PATH", "/tmp/hdfs-site.xml");

        this.gosecConfig = com.typesafe.config.ConfigFactory.load();

        List<String> instancesJava = new ArrayList<>();
        instancesJava.add(gosecConfig.getString("plugin.instance"));
        this.instances = JavaConversions.asScalaBuffer(instancesJava).toList();

        List<String> servicesJava = new ArrayList<>();
        servicesJava.add("hdfs");
        this.services = JavaConversions.asScalaBuffer(servicesJava).toList();

        List<String> usernamesJava = new ArrayList<>();
        usernamesJava.add(username);
        Seq<String> usernames = JavaConversions.asScalaBuffer(usernamesJava).toList();

        List<String> groupsJava = new ArrayList<>();
        Seq<String> groups = JavaConversions.asScalaBuffer(groupsJava).toList();

        Identities ids = new Identities(usernames, groups);
        this.opIds = new Some<>(ids);

    }

    public void connect() throws IOException {
        Configuration conf = new Configuration();
        conf.addResource(new Path(this.coreSitePath));
        conf.addResource(new Path(this.hdfsSitePath));

        UserGroupInformation.setConfiguration(conf);
        UserGroupInformation.loginUserFromKeytab(this.username + "@" + this.realm, this.pathKeytab);
        this.fs = FileSystem.get(conf);
    }

    public void addPolicy(String filename, String action, String permission, boolean recursive) {
        Path filePath = new Path(filename);
        Path parent = filePath.getParent();
        ArrayList<Resource> resources = this.addResources(parent, new ArrayList<>());

        List<Acl> acls = resources.stream()
                .map(r -> new Acl(r, Action$.MODULE$.fromString("Read"), Permission$.MODULE$.fromString("Allow"),
                        false)).collect(Collectors.toList());

        // Here we create the actual policy for the resource
        Resource childResource = new Resource("hdfs", instances, gosecConfig.getString("authorizer.resource.type"),
                filename);
        Acl acl = new Acl(childResource, Action$.MODULE$.fromString(action), Permission$.MODULE$.fromString(permission),
                recursive);

        // Apart from the specific permission, the HDFS plugin NEEDS "Read Allow" on the resource
        if (!action.equals("Read") && !recursive) {
            acls.add(new Acl(childResource, Action$.MODULE$.fromString("Read"), Permission$.MODULE$.fromString("Allow"),
                    false));
        }
        acls.add(acl);
        this.saveOrUpdatePolicy(acls);

    }

    /*
     * This method creates Resources recursively to be able to add "/", "/test1", "/test1/test2", and so on from a given path
     */
    private ArrayList<Resource> addResources(Path path, ArrayList<Resource> resourcesList) {
        Resource resource = new Resource("hdfs", this.instances, gosecConfig.getString("authorizer.resource.type"),
                path.toString());
        resourcesList.add(resource);
        if (path.toString().equals("/")) {
            return resourcesList;
        } else {
            return this.addResources(path.getParent(), resourcesList);
        }
    }

    private void saveOrUpdatePolicy(List<Acl> acls) {
        if (!policyService.exists(rootPolicyName)) {
            policyService.savePolicy(new Policy(rootPolicyName, rootPolicyDesc, opIds, services, instances,
                    JavaConversions.asScalaBuffer(acls).toList()));
        } else {
            Policy existingPolicy = policyService.get(rootPolicyName);
            List<Acl> oldAcls = JavaConversions.seqAsJavaList(existingPolicy.acls());
            acls.addAll(oldAcls);
            scala.collection.immutable.List<Acl> scalaAcls = JavaConversions.asScalaBuffer(acls).toList();
            Policy newPolicy = new Policy(rootPolicyName, rootPolicyDesc, opIds, services, instances, scalaAcls);
            policyService.updatePolicy(newPolicy);
        }
    }

    public String readFile(String filename) throws IOException {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(fs.open(new Path(filename))));
            String total = "";
            String line;
            while ((line = reader.readLine()) != null) {
                total += line;
            }
            this.operationResult = "Success";
            return total;
        } catch (IOException e) {
            this.operationResult = "Failure";
            throw e;
        }
    }

    public void obtainFullAccess() {
        this.revokeFullAccess();
        Resource rootFolder = new Resource("hdfs", instances, gosecConfig.getString("authorizer.resource.type"), "/");

        List<Acl> acls = new ArrayList<>();
        acls.add(
                new Acl(rootFolder, Action$.MODULE$.fromString("Read"), Permission$.MODULE$.fromString("Allow"), true));
        acls.add(new Acl(rootFolder, Action$.MODULE$.fromString("Write"), Permission$.MODULE$.fromString("Allow"),
                true));
        acls.add(new Acl(rootFolder, Action$.MODULE$.fromString("Delete"), Permission$.MODULE$.fromString("Allow"),
                true));
        // No need for Execute permissions. Not supported on the HDFS Plugin
        policyService.save(new Policy(rootPolicyName, rootPolicyDesc, opIds, services, instances,
                JavaConversions.asScalaBuffer(acls).toList()));
    }

    public void revokeFullAccess() {
        policyService.delete(rootPolicyName);
    }

    public boolean createFile(String filename) {
        try {
            boolean result = this.fs.createNewFile(new Path(filename));
            if (result) {
                this.createdFiles.add(filename);
                this.operationResult = "Success";
            } else {
                this.operationResult = "Failure";
            }
            return result;
        } catch (IOException e) {
            logger.debug(e.getMessage());
            this.operationResult = "Failure";
            return false;
        }
    }

    public boolean deleteFile(String filename) {
        try {
            boolean result = this.fs.delete(new Path(filename), false);
            if (result) {
                this.createdFiles = this.createdFiles.stream().filter(a -> !a.equals(filename))
                        .collect(Collectors.toSet());
                this.operationResult = "Success";
            } else {
                this.operationResult = "Failure";
            }
            return result;
        } catch (IOException e) {
            logger.debug(e.getMessage());
            this.operationResult = "Failure";
            return false;
        }
    }

    public boolean writeToFile(String filename, String content) {
        try {
            DataOutputStream dos = this.fs.append(new Path(filename));
            dos.writeChars(content);
            dos.close();

            // Horrible hack because Strings read from HDFS have null chars interpolated (doubling string length)
            String result = this.readFile(filename).replaceAll("[\u0000-\u001f]", "");
            if (result.equals(content)) {
                this.operationResult = "Success";
                return true;
            } else {
                this.operationResult = "Failure";
                return false;
            }
        } catch (IOException e) {
            logger.debug(e.getMessage());
            this.operationResult = "Failure";
            return false;
        }
    }

    public void cleanCreatedFiles() {
        this.obtainFullAccess();
        this.createdFiles.forEach(f -> {
            try {
                fs.delete(new Path(f), false);
            } catch (IOException e) {
                logger.error(e.toString());
            }
        });
        this.createdFiles.clear();
        this.revokeFullAccess();
    }

    public String getOperationResult() {
        return operationResult;
    }
}
