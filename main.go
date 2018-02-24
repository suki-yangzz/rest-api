package main

import (
	"bytes"
	"cloud.google.com/go/storage"
	"encoding/json"
	"fmt"
	"git.openstack.org/openstack/golang-client/objectstorage/v1"
	"git.openstack.org/openstack/golang-client/openstack"
	"github.com/rackspace/gophercloud"
	gophercloud_openstack "github.com/rackspace/gophercloud/openstack"
	"golang.org/x/net/context"
	"google.golang.org/api/option"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	//"github.com/rackspace/gophercloud/openstack/objectstorage/v1/containers"
	"github.com/rackspace/gophercloud/openstack/compute/v2/extensions/secgroups"
)

type config struct {
	Host        string
	Username    string
	Password    string
	ProjectID   string
	ProjectName string
	Container   string
	ImageRegion string
	Debug       bool
}

// UpdateOpts specifies the base attributes that may be updated on an existing server.
type UpdateOpts struct {
	// Required - the ID of the group that this rule will be added to.
	ParentGroupID string `json:"parent_group_id"`

	// Required - the lower bound of the port range that will be opened.
	FromPort int `json:"from_port"`

	// Required - the upper bound of the port range that will be opened.
	ToPort int `json:"to_port"`

	// Required - the protocol type that will be allowed, e.g. TCP.
	IPProtocol string `json:"ip_protocol"`

	// ONLY required if FromGroupID is blank. This represents the IP range that
	// will be the source of network traffic to your security group. Use
	// 0.0.0.0/0 to allow all IP addresses.
	CIDR string `json:"cidr,omitempty"`

	// ONLY required if CIDR is blank. This value represents the ID of a group
	// that forwards traffic to the parent group. So, instead of accepting
	// network traffic from an entire IP range, you can instead refine the
	// inbound source by an existing security group.
	FromGroupID string `json:"group_id,omitempty"`
}

// UpdateOptsBuilder allows extensions to add additional attributes to the Update request.
type UpdateOptsBuilder interface {
	ToSecurityGroupsUpdateMap() map[string]interface{}
}

// ToServerUpdateMap formats an UpdateOpts structure into a request body.
func (opts UpdateOpts) ToSecurityGroupsUpdateMap() map[string]interface{} {
	secgroups := make(map[string]string)
	if opts.ParentGroupID != "" {
		secgroups["name"] = opts.ParentGroupID
	}
	if opts.FromPort != nil {
		secgroups["accessIPv4"] = opts.AccessIPv4
	}
	if opts.AccessIPv6 != "" {
		secgroups["accessIPv6"] = opts.AccessIPv6
	}
	return map[string]interface{}{"server": server}
}

func gcclient() {
	ctx := context.Background()

	storageClient, err := storage.NewClient(ctx, option.WithCredentialsFile("service_account_file.json"))
	if err != nil {
		log.Fatal(err)
	}

	// Read the object1 from bucket.
	rc, err := storageClient.Bucket("sssyayayiooo-bucket").Object("data.json").NewReader(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rc.Close()
	body, err := ioutil.ReadAll(rc)
	if err != nil {
		log.Fatal(err)
	}
	var data interface{}
	fmt.Println(json.Unmarshal(body, &data))
}

func openstackclient() {
	config := &config{}
	config.Host = "https://keystone.ams1.cloud.ecg.so/v2.0"
	config.ProjectName = "dev-zhenzyang"
	config.Username = "zhenzyang"
	config.Password = "!PzkydPj@pa8pvAA"
	config.Container = "test"

	// Before working with object storage we need to authenticate with a project
	// that has active object storage.
	// Authenticate with a project name, username, password.
	creds := openstack.AuthOpts{
		AuthUrl:     config.Host,
		ProjectName: config.ProjectName,
		Username:    config.Username,
		Password:    config.Password,
	}
	auth, err := openstack.DoAuthRequest(creds)
	if err != nil {
		panicString := fmt.Sprint("There was an error authenticating:", err)
		panic(panicString)
	}
	if !auth.GetExpiration().After(time.Now()) {
		panic("There was an error. The auth token has an invalid expiration.")
	}

	// Find the endpoint for object storage.
	url, err := auth.GetEndpoint("object-store", "")
	if url == "" || err != nil {
		panic("object-store url not found during authentication")
	}

	// Make a new client with these creds
	sess, err := openstack.NewSession(nil, auth, nil)
	if err != nil {
		panicString := fmt.Sprint("Error crating new Session:", err)
		panic(panicString)
	}

	hdr, err := objectstorage.GetAccountMeta(sess, url)
	if err != nil {
		panicString := fmt.Sprint("There was an error getting account metadata:", err)
		panic(panicString)
	}
	_ = hdr

	// Create a new container.
	var headers http.Header = http.Header{}
	headers.Add("X-Log-Retention", "true")
	if err = objectstorage.PutContainer(sess, url+"/"+config.Container, headers); err != nil {
		panicString := fmt.Sprint("PutContainer Error:", err)
		panic(panicString)
	}

	// Get a list of all the containers at the selected endoint.
	containersJson, err := objectstorage.ListContainers(sess, 0, "", url)
	if err != nil {
		panic(err)
	}

	type containerType struct {
		Name         string
		Bytes, Count int
	}
	containersList := []containerType{}

	if err = json.Unmarshal(containersJson, &containersList); err != nil {
		panic(err)
	}

	found := false
	for i := 0; i < len(containersList); i++ {
		if containersList[i].Name == config.Container {
			found = true
		}
	}
	if !found {
		panic("Created container is missing from downloaded containersList")
	}

	// Set and Get container metadata.
	headers = http.Header{}
	headers.Add("X-Container-Meta-fubar", "false")
	if err = objectstorage.SetContainerMeta(sess, url+"/"+config.Container, headers); err != nil {
		panic(err)
	}

	hdr, err = objectstorage.GetContainerMeta(sess, url+"/"+config.Container)
	if err != nil {
		panicString := fmt.Sprint("GetContainerMeta Error:", err)
		panic(panicString)
	}
	if hdr.Get("X-Container-Meta-fubar") != "false" {
		panic("container meta does not match")
	}

	// Create an object in a container.
	var fContent []byte
	srcFile := "data.json"
	fContent, err = ioutil.ReadFile(srcFile)
	if err != nil {
		panic(err)
	}

	headers = http.Header{}
	headers.Add("X-Container-Meta-fubar", "false")
	object := config.Container + "/" + srcFile
	if err = objectstorage.PutObject(sess, &fContent, url+"/"+object, headers); err != nil {
		panic(err)
	}
	objectsJson, err := objectstorage.ListObjects(sess, 0, "", "", "", "",
		url+"/"+config.Container)

	type objectType struct {
		Name, Hash, Content_type, Last_modified string
		Bytes                                   int
	}
	objectsList := []objectType{}

	if err = json.Unmarshal(objectsJson, &objectsList); err != nil {
		panic(err)
	}
	found = false
	for i := 0; i < len(objectsList); i++ {
		if objectsList[i].Name == srcFile {
			found = true
		}
	}
	if !found {
		panic("created object is missing from the objectsList")
	}

	// Manage object metadata
	headers = http.Header{}
	headers.Add("X-Object-Meta-fubar", "true")
	if err = objectstorage.SetObjectMeta(sess, url+"/"+object, headers); err != nil {
		panicString := fmt.Sprint("SetObjectMeta Error:", err)
		panic(panicString)
	}
	hdr, err = objectstorage.GetObjectMeta(sess, url+"/"+object)
	if err != nil {
		panicString := fmt.Sprint("GetObjectMeta Error:", err)
		panic(panicString)
	}
	if hdr.Get("X-Object-Meta-fubar") != "true" {
		panicString := fmt.Sprint("SetObjectMeta Error:", err)
		panic(panicString)
	}

	// Retrieve an object and check that it is the same as what as uploaded.
	_, body, err := objectstorage.GetObject(sess, url+"/"+object)
	if err != nil {
		panicString := fmt.Sprint("GetObject Error:", err)
		panic(panicString)
	}
	if !bytes.Equal(fContent, body) {
		panicString := fmt.Sprint("GetObject Error:", "byte comparison of uploaded != downloaded")
		panic(panicString)
	}

	// Duplication (Copy) an existing object.
	if err = objectstorage.CopyObject(sess, url+"/"+object, "/"+object+".dup"); err != nil {
		panicString := fmt.Sprint("CopyObject Error:", err)
		panic(panicString)
	}

	//// Delete the objects.
	//if err = objectstorage.DeleteObject(sess, url+"/"+object); err != nil {
	//    panicString := fmt.Sprint("DeleteObject Error:", err)
	//    panic(panicString)
	//}
	//if err = objectstorage.DeleteObject(sess, url+"/"+object+".dup"); err != nil {
	//    panicString := fmt.Sprint("DeleteObject Error:", err)
	//    panic(panicString)
	//}
	//
	//// Delete the container that was previously created.
	//if err = objectstorage.DeleteContainer(sess, url+"/"+config.Container); err != nil {
	//    panicString := fmt.Sprint("DeleteContainer Error:", err)
	//    panic(panicString)
	//}
}

func gopercloudclient() {
	authOpts := gophercloud.AuthOptions{
		IdentityEndpoint: "https://keystone.ams1.cloud.ecg.so/v2.0",
		Username:         "zhenzyang",
		Password:         "!PzkydPj@pa8pvAA",
		TenantID:         "611263aa9d2e4557a7416fd0ee115cca",
	}
	provider, err := gophercloud_openstack.AuthenticatedClient(authOpts)
	if err != nil {
		log.Fatal(err)
	}

	//client, err := gophercloud_openstack.NewObjectStorageV1(provider, gophercloud.EndpointOpts{
	//    Region: "ams1",
	//})
	//if err != nil {
	//    log.Fatal(err)
	//}
	//// We have the option of passing in configuration options for our new container
	////opts := containers.CreateOpts{
	////    ContainerSyncTo: "test_new",
	////    Metadata:        map[string]string{"author": "admin"},
	////}
	//
	//res := containers.Create(client, "test1", nil)
	//
	//// If we want to extract information out from the response headers, we can.
	//// The first return value will be http.Header (alias of map[string][]string).
	//headers, err := res.ExtractHeader()
	//if err != nil {
	//    log.Fatal(err)
	//}
	//log.Fatal(headers)
	//log.Fatal(res)

	client, err := gophercloud_openstack.NewComputeV2(provider, gophercloud.EndpointOpts{
		Region: "ams1",
	})

	groupOpts := secgroups.CreateOpts{
		Name:        "MySecGroup",
		Description: "something",
	}

	group, err := secgroups.Create(client, groupOpts).Extract()
	if err != nil {
		log.Fatal(err)
	}

	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: group.ID,
		FromPort:      22,
		ToPort:        22,
		IPProtocol:    "TCP",
		CIDR:          "0.0.0.0/0",
	}

	ruleOpts := secgroups.Update("ccba6dc0-0e78-435d-bed5-47f7cba807fa")

	rule, err := secgroups.CreateRule(client, ruleOpts).Extract()
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(rule)
}

// our main function
func main() {
	gopercloudclient()
}
