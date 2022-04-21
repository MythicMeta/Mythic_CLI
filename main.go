// @author: its_a_feature_
// This code is to administer Mythic 2.2.4+ configurations
package main

import (
    "fmt"
    "os"
    "github.com/spf13/viper"
    "sort"
    "log"
    "crypto/rand"
    "strings"
    "math/big"
    "github.com/docker/docker/client"
    "github.com/docker/docker/api/types"
    "context"
    "encoding/binary"
    "os/exec"
    "path/filepath"
    "bufio"
    "io"
    "io/ioutil"
    "path"
    "text/tabwriter"
    "net"
    "strconv"
    "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"
	"net/http"
	"crypto/tls"
	"github.com/streadway/amqp"
)

var mythicServices = []string{
	"mythic_postgres",
	"mythic_react",
	"mythic_server",
	"mythic_redis",
	"mythic_nginx",
	"mythic_rabbitmq",
	"mythic_graphql",
	"mythic_documentation",
	"mythic_sync",
}
var mythicEnv = viper.New()
var mythicCliVersion = "0.0.6"
var buildArguments = []string{}
func stringInSlice(value string, list []string) bool {
	for _, e := range list {
		if e == value {
			return true
		}
	}
	return false
}
func removeExclusionsFromSlice(group string, suppliedList[]string) []string {
	// use the EXCLUDED_C2_PROFILES and EXCLUDED_PAYLOAD_TYPES variables to limit what we start
	var exclusion_list []string
	if group == "c2" {
		exclusion_list = strings.Split(mythicEnv.GetString("EXCLUDED_C2_PROFILES"), ",")
	} else if group == "payload" {
		exclusion_list = strings.Split(mythicEnv.GetString("EXCLUDED_PAYLOAD_TYPES"), ",")
	}
	var final_list []string
	for _, element := range suppliedList {
		if !stringInSlice(element, exclusion_list) {
			final_list = append(final_list, element)
		} else {
			fmt.Printf("[*] Skipping %s because it's in an exclusion list\n", element)
		}
	}
	return final_list
}
func updateEnvironmentVariables(originalList []string, updates []string) []string{
	var finalList []string
	for _, entry := range originalList {
		entryPieces := strings.Split(entry, "=")
		found := false
		for _, update := range updates {
			updatePieces := strings.Split(update, "=")
			if updatePieces[0] == entryPieces[0] {
				// the current env vars has a key that we want to update, so don't include the old version
				found = true
			}
		}
		if !found {
			finalList = append(finalList, entry)
		}
	}
	for _, update := range updates {
		finalList = append(finalList, update)
	}
	return finalList
}
func displayHelp(){
    fmt.Println("mythic-cli usage ( v", mythicCliVersion, "):")
    fmt.Println("*************************************************************")
    fmt.Println("*** source code: https://github.com/MythicMeta/Mythic_CLI ***")
	fmt.Println("*************************************************************")
    fmt.Println("  help")
    fmt.Println("  mythic {start|stop} [service name...]")
    fmt.Println("  start | restart")
    fmt.Println("    Stops and Starts all of Mythic - alias for 'mythic start'")
    fmt.Println("  stop")
    fmt.Println("    Stop all of Mythic - alias for 'mythic stop'")
    fmt.Println("  c2 {start|stop|add|remove|list} [c2profile ...]")
    fmt.Println("      The add/remove subcommands adjust the docker-compose file, not manipulate files on disk")
    fmt.Println("         to manipulate files on disk, use 'install' and 'uninstall' commands")
    fmt.Println("  payload {start|stop|add|remove|list} [payloadtype ...]")
    fmt.Println("      The add/remove subcommands adjust the docker-compose file, not manipulate files on disk")
    fmt.Println("         to manipulate files on disk, use 'install' and 'uninstall' commands")
    fmt.Println("  config")
    fmt.Println("      *no parameters will dump the entire config*")
    fmt.Println("      get [varname ...]")
    fmt.Println("      set <var name> <var value>")
    fmt.Println("      payload (dump out remote payload configuration variables)")
    fmt.Println("      c2 (dump out remote c2 configuration variables)")
    fmt.Println("  database reset")
    fmt.Println("  install ")
    fmt.Println("      github <url> [branch name] [-f]")
    fmt.Println("      folder <path to folder> [-f]")
    fmt.Println("      -f forces the removal of the currently installed version and overwrites with the new, otherwise will prompt you")
    fmt.Println("         * this command will manipulate files on disk and update docker-compose")
    fmt.Println("  uninstall {name1 name2 name2 ...}")
    fmt.Println("      (this command removes the payload or c2 profile from disk and updates docker-compose)")
    fmt.Println("  status")
    fmt.Println("  logs <container name>")
    fmt.Println("  mythic_sync")
    fmt.Println("      install github [url] [branch name]")
    fmt.Println("         * if no url is provided, https://github.com/GhostManager/mythic_sync will be used")
    fmt.Println("      install folder <path to folder>")
    fmt.Println("      uninstall")
    fmt.Println("  version")
    fmt.Println("  test")
    fmt.Println("      test connectivity to RabbitMQ and the Mythic UI")
}
func generateRandomPassword(pw_length int) string{
    chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    var b strings.Builder
    for i := 0; i < pw_length; i++ {
    	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
    	if err != nil {
    		log.Fatalf("[-] Failed to generate random number for password generation\n")
    	}
        b.WriteRune(chars[nBig.Int64()])
    }
    return b.String() 
}
func setMythicConfigDefaultValues(){
    // nginx configuration
    mythicEnv.SetDefault("nginx_port", 7443)
    mythicEnv.SetDefault("nginx_host", "mythic_nginx")
    mythicEnv.SetDefault("nginx_bind_localhost_only", false)
    mythicEnv.SetDefault("nginx_use_ssl", true)
    // mythic react UI configuration
    mythicEnv.SetDefault("mythic_react_host", "mythic_react")
    mythicEnv.SetDefault("mythic_react_port", 3000)
    mythicEnv.SetDefault("mythic_react_bind_localhost_only", true)
    // mythic server configuration
    mythicEnv.SetDefault("documentation_host", "mythic_documentation")
    mythicEnv.SetDefault("documentation_port", 8090)
    mythicEnv.SetDefault("documentation_bind_localhost_only", true)
    mythicEnv.SetDefault("mythic_debug", false)
    mythicEnv.SetDefault("mythic_server_port", 17443)
    mythicEnv.SetDefault("mythic_server_host", "mythic_server")
    mythicEnv.SetDefault("mythic_server_bind_localhost_only", true)
    mythicEnv.SetDefault("mythic_server_dynamic_ports", "7000-7010")
    // postgres configuration
    mythicEnv.SetDefault("postgres_host", "mythic_postgres")
    mythicEnv.SetDefault("postgres_port", 5432)
    mythicEnv.SetDefault("postgres_bind_localhost_only", true)
    mythicEnv.SetDefault("postgres_db", "mythic_db")
    mythicEnv.SetDefault("postgres_user", "mythic_user")
    mythicEnv.SetDefault("postgres_password", generateRandomPassword(30))
    // rabbitmq configuration
    mythicEnv.SetDefault("rabbitmq_host", "mythic_rabbitmq")
    mythicEnv.SetDefault("rabbitmq_port", 5672)
    mythicEnv.SetDefault("rabbitmq_bind_localhost_only", true)
    mythicEnv.SetDefault("rabbitmq_user", "mythic_user")
    mythicEnv.SetDefault("rabbitmq_password", generateRandomPassword(30))
    mythicEnv.SetDefault("rabbitmq_vhost", "mythic_vhost")
    // jwt configuration
    mythicEnv.SetDefault("jwt_secret", generateRandomPassword(30))
    // hasura configuration
    mythicEnv.SetDefault("hasura_host", "mythic_graphql")
    mythicEnv.SetDefault("hasura_port", 8080)
    mythicEnv.SetDefault("hasura_bind_localhost_only", true)
    mythicEnv.SetDefault("hasura_secret", generateRandomPassword(30))
    // redis configuration
    mythicEnv.SetDefault("redis_port", 6379)
    mythicEnv.SetDefault("redis_host", "mythic_redis")
    mythicEnv.SetDefault("redis_bind_localhost_only", true)
    // docker-compose configuration
    mythicEnv.SetDefault("COMPOSE_PROJECT_NAME", "mythic")
    mythicEnv.SetDefault("REBUILD_ON_START", true)
    // Mythic instance configuration
    mythicEnv.SetDefault("mythic_admin_user", "mythic_admin")
    mythicEnv.SetDefault("mythic_admin_password", generateRandomPassword(30))
    mythicEnv.SetDefault("default_operation_name", "Operation Chimera")
    mythicEnv.SetDefault("allowed_ip_blocks", "0.0.0.0/0")
    mythicEnv.SetDefault("server_header", "nginx 1.2")
    mythicEnv.SetDefault("web_log_size", 1024000)
    mythicEnv.SetDefault("web_keep_logs", false)
    mythicEnv.SetDefault("siem_log_name", "")
    mythicEnv.SetDefault("excluded_payload_types", "")
    mythicEnv.SetDefault("excluded_c2_profiles", "")
    // PayloadType / C2 / Translator configuration
    mythicEnv.SetDefault("mythic_environment", "production")
}
func parseMythicEnvironmentVariables(){
	setMythicConfigDefaultValues()
    mythicEnv.SetConfigName(".env")
    mythicEnv.SetConfigType("env")
    mythicEnv.AddConfigPath(getCwdFromExe())
    mythicEnv.AutomaticEnv()
    if !fileExists(filepath.Join(getCwdFromExe(), ".env")) {
    	_, err := os.Create(filepath.Join(getCwdFromExe(), ".env"))
    	if err != nil {
    		log.Fatalf("[-] .env doesn't exist and couldn't be created")
    	}
    }
    if err := mythicEnv.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            log.Fatalf("[-] Error while reading in .env file: %s", err)
        } else {
            log.Fatalf("[-]Error while parsing .env file: %s", err)
        }
    }
    portChecks := map[string][]string{
		"MYTHIC_SERVER_HOST": []string{
			"MYTHIC_SERVER_PORT",
			"mythic_server",
		},
		"POSTGRES_HOST": []string{
			"POSTGRES_PORT",
			"mythic_postgres",
		},
		"HASURA_HOST": []string{
			"HASURA_PORT",
			"mythic_graphql",
		},
		"RABBITMQ_HOST": []string{
			"RABBITMQ_PORT",
			"mythic_rabbitmq",
		},
		"DOCUMENTATION_HOST": []string{
			"DOCUMENTATION_PORT",
			"mythic_documentation",
		},
		"NGINX_HOST": []string{
			"NGINX_PORT",
			"mythic_nginx",
		},
		"REDIS_HOST": []string{
			"REDIS_PORT",
			"mythic_redis",
		},
		"MYTHIC_REACT_HOST": []string{
			"MYTHIC_REACT_PORT",
			"mythic_react",
		},
	}
	for key, val := range portChecks {
		if mythicEnv.GetString(key) == "127.0.0.1" {
			mythicEnv.Set(key, val[1])
		}
	}
	writeMythicEnvironmentVariables()
}
func writeMythicEnvironmentVariables(){
	c := mythicEnv.AllSettings()
    // to make it easier to read and look at, get all the keys, sort them, and display variables in order
    keys := make([]string, 0, len(c))
    for k := range c {
    	keys = append(keys, k)
    }
    sort.Strings(keys)
    f, err := os.Create(filepath.Join(getCwdFromExe(), ".env"))
    if err != nil {
    	log.Fatalf("[-] Error writing out environment!\n%v", err)
    }
    defer f.Close()
    for _, key := range keys {
    	if len(mythicEnv.GetString(key)) == 0{
    		_, err = f.WriteString(fmt.Sprintf("%s=\n", strings.ToUpper(key)))
    	}else{
    		_, err = f.WriteString(fmt.Sprintf("%s=\"%s\"\n", strings.ToUpper(key), mythicEnv.GetString(key)))
    	}
    	
    	if err != nil {
    		log.Fatalf("[-] Failed to write out environment!\n%v", err)
    	}
    }
    return
}
func printShellCommands(variables map[string]string){
	fmt.Printf("\n[*] Shell commands for Linux\n")
	for key, value := range variables {
		fmt.Printf("export %s=\"%s\"\n", strings.ToUpper(key), value)
	}
	fmt.Printf("export MYTHIC_NAME=\"agent name here\"\n")
	fmt.Printf("\n[*] Shell commands for Linux on one line\n")
	var output []string
	for key, value := range variables {
		output = append(output, fmt.Sprintf("export %s=\"%s\"", strings.ToUpper(key), value))
	}
	output = append(output, fmt.Sprintf("export MYTHIC_NAME=\"agent name here\""))
	fmt.Printf(strings.Join(output[:], "; "))
	fmt.Printf("\n\n[*] PowerShell commands for Windows\n")
	for key, value := range variables {
		fmt.Printf("$env:%s=\"%s\"\n", strings.ToUpper(key), value)
	}
	fmt.Printf("$env:MYTHIC_NAME=\"agent name here\"\n")
	var winPowerShellOutput []string
	fmt.Printf("\n[*] PowerShell commands for Windows on one line\n")
	for key, value := range variables {
		winPowerShellOutput = append(winPowerShellOutput, fmt.Sprintf("$env:%s=\"%s\"", strings.ToUpper(key), value))
	}
	winPowerShellOutput = append(winPowerShellOutput, fmt.Sprintf("$env:MYTHIC_NAME=\"agent name here\""))
	fmt.Printf(strings.Join(winPowerShellOutput[:], " && "))
	fmt.Printf("\n\n[*] CMD commands for Windows\n")
	for key, value := range variables {
		fmt.Printf("SET %s=\"%s\"\n", strings.ToUpper(key), value)
	}
	fmt.Printf("SET MYTHIC_NAME=\"agent name here\"\n")
	var winOutput []string
	fmt.Printf("\n[*] Shell commands for Windows on one line\n")
	for key, value := range variables {
		winOutput = append(winOutput, fmt.Sprintf("SET %s=\"%s\"", strings.ToUpper(key), value))
	}
	winOutput = append(winOutput, fmt.Sprintf("SET MYTHIC_NAME=\"agent name here\""))
	fmt.Printf(strings.Join(winOutput[:], " && "))
	fmt.Printf("\n\n")
}
func env(args []string){
    if len(args) == 0 {
        // we want to just get all of the environment variables that mythic uses
        c := mythicEnv.AllSettings()
        // to make it easier to read and look at, get all the keys, sort them, and display variables in order
        keys := make([]string, 0, len(c))
        for k := range c {
        	keys = append(keys, k)
        }
        sort.Strings(keys)
        for _, key := range keys {
        	fmt.Println(strings.ToUpper(key), "=", mythicEnv.Get(key))
        }
        return
    }
    switch args[0] {
    case "get":
        if len(args) == 1 {
            log.Fatal("[-] Must specify name of variable to get")
        }
        for i := 1; i < len(args[1:]) + 1; i++ {
            val := mythicEnv.Get(args[i])
            fmt.Println(strings.ToUpper(args[i]), "=", val)
        }
    case "set":
		if len(args) != 3{
			log.Fatalf("[-] Must supply config name and config value")
		}
		if strings.ToLower(args[2]) == "true" {
			mythicEnv.Set(args[1], true)
		}else if strings.ToLower(args[2]) == "false" {
			mythicEnv.Set(args[1], false)
		}else{
			mythicEnv.Set(args[1], args[2])
		}
		mythicEnv.Get(args[1])
		writeMythicEnvironmentVariables()
		fmt.Printf("[+] Successfully updated configuration in .env\n")

	case "payload":
		fixRabbitMqLocalHost := false
		// get all of the configuration variables for a remote payload type
		fmt.Printf("\n[*] When using a Payload Type that runs outside of this Mythic instance (i.e. remote Computer, remote VM, etc), you need to pass in configuration information\n")
		fmt.Printf("    Use these environment variables for your remote Payload Type to make sure it can properly connect to Mythic\n")
		variables := map[string]string{
			"MYTHIC_USERNAME": mythicEnv.GetString("RABBITMQ_USER"),
			"MYTHIC_PASSWORD": mythicEnv.GetString("RABBITMQ_PASSWORD"),
			"MYTHIC_VIRTUAL_HOST": mythicEnv.GetString("RABBITMQ_VHOST"),
			"MYTHIC_HOST": mythicEnv.GetString("RABBITMQ_HOST"),
			"MYTHIC_PORT": mythicEnv.GetString("RABBITMQ_PORT"),
		}
		printShellCommands(variables)
		if mythicEnv.GetString("RABBITMQ_HOST") == "mythic_rabbitmq" || mythicEnv.GetString("RABBITMQ_HOST") == "127.0.0.1" {
			if !mythicEnv.GetBool("rabbitmq_bind_localhost_only") {
				fmt.Printf("[-] Environment variable, MYTHIC_HOST, is not set to a public ip\n")
				fmt.Printf("    Make sure to update it to the correct routable IP address or add an appropriate hostname to your DNS in your remote configuration\n")
			}
		}
		if mythicEnv.GetBool("rabbitmq_bind_localhost_only") {
			fmt.Printf("[-] Service, mythic_rabbitmq, is currently bound to 127.0.0.1, so a remote agent will be unable to connect to it\n")
			fmt.Printf("    To fix this, set the \"RABBITMQ_BIND_LOCALHOST_ONLY\" variable to \"false\" and restart mythic\n")
			fixRabbitMqLocalHost = true
		}
		if fixRabbitMqLocalHost {
			autoFix := askConfirm("\nDo you want the service to be externally available and Mythic restarted?")
			if autoFix {
				mythicEnv.Set("rabbitmq_bind_localhost_only", false)
				writeMythicEnvironmentVariables()
				startStop("start", "mythic", []string{})
				env(args)
			}
		}
		
	case "c2":
		fmt.Printf("\n[*] When using a C2 Profile that runs outside of this Mythic instance (i.e. remote Computer, remote VM, etc), you need to pass in configuration information\n")
		fmt.Printf("    Use these environment variables for your remote C2 Profile to make sure it can properly connect to Mythic\n")
		fixRabbitMqLocalHost := false
		fixMythicServerLocalHost := false
		variables := map[string]string{
			"MYTHIC_USERNAME": mythicEnv.GetString("RABBITMQ_USER"),
			"MYTHIC_PASSWORD": mythicEnv.GetString("RABBITMQ_PASSWORD"),
			"MYTHIC_VIRTUAL_HOST": mythicEnv.GetString("RABBITMQ_VHOST"),
			"MYTHIC_HOST": mythicEnv.GetString("RABBITMQ_HOST"),
			"MYTHIC_PORT": mythicEnv.GetString("RABBITMQ_PORT"),
			"MYTHIC_ADDRESS": "http://" + mythicEnv.GetString("MYTHIC_SERVER_HOST") + ":" + mythicEnv.GetString("MYTHIC_SERVER_PORT") + "/api/v1.4/agent_message",
			"MYTHIC_WEBSOCKET": "ws://" + mythicEnv.GetString("MYTHIC_SERVER_HOST") + ":" + mythicEnv.GetString("MYTHIC_SERVER_PORT") + "/ws/agent_message",
		}
		printShellCommands(variables)
		if mythicEnv.GetString("RABBITMQ_HOST") == "mythic_rabbitmq" || mythicEnv.GetString("RABBITMQ_HOST") == "127.0.0.1" {
			if !mythicEnv.GetBool("rabbitmq_bind_localhost_only") {
				fmt.Printf("[-] Environment variable, MYTHIC_HOST, is not set to a public ip\n")
				fmt.Printf("    Make sure to update it to the correct routable IP address or add an appropriate hostname to your DNS in your remote configuration\n")
			}
		}
		if mythicEnv.GetString("MYTHIC_SERVER_HOST") == "mythic_server" || mythicEnv.GetString("MYTHIC_SERVER_HOST") == "127.0.0.1" {
			if !mythicEnv.GetBool("mythic_server_bind_localhost_only") {
				fmt.Printf("[-] Environment variables, MYTHIC_ADDRESS and MYTHIC_WEBSOCKET, do not include public IP addresses\n")
				fmt.Printf("    Make sure to update it to the correct routable IP address or add an appropriate hostname to your DNS in your remote configuration\n")
			}
		}
		if mythicEnv.GetBool("rabbitmq_bind_localhost_only") {
			fmt.Printf("[-] Service, mythic_rabbitmq, is currently listening on 127.0.0.1, so a remote agent will be unable to connect to it\n")
			fmt.Printf("    To fix this, set the \"RABBITMQ_BIND_LOCALHOST_ONLY\" variable to \"false\" and restart mythic\n")
			fixRabbitMqLocalHost = true
		}
		if mythicEnv.GetBool("mythic_server_bind_localhost_only"){
			fmt.Printf("[-] Service, mythic_server, is currently listening on 127.0.0.1, so a remote agent will be unable to connect to it to send C2 traffic\n")
			fmt.Printf("    To fix this, set the \"MYTHIC_SERVER_BIND_LOCALHOST_ONLY\" variable to \"false\" and restart mythic\n")
			fixMythicServerLocalHost = true
		}
		if fixRabbitMqLocalHost || fixMythicServerLocalHost {
			autoFix := askConfirm("\nDo you want service to be externally available and Mythic restarted?")
			if autoFix {
				mythicEnv.Set("rabbitmq_bind_localhost_only", false)
				mythicEnv.Set("mythic_server_bind_localhost_only", false)
				writeMythicEnvironmentVariables()
				startStop("start", "mythic", []string{})
				env(args)
			}
		}
    default:
        fmt.Println("[-] Unknown env subcommand:", args[0])
    }
}
func isServiceRunning(service string) bool {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("[-] Failed to get client connection to Docker: %v", err)
	}
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{
		All: true,
	})
	if err != nil {
		log.Fatalf("[-] Failed to get container list from Docker: %v", err)
	}
	if len(containers) > 0 {
		for _, container := range containers {
			if container.Labels["name"] == strings.ToLower(service) {
				return true
			}
		}
	}
	return false
}
func getElementsOnDisk(group string) []string {
	var path string 
	if(group == "payload"){
		path = "Payload_Types"
	}else if(group == "c2"){
		path = "C2_Profiles"
	}else{
		log.Fatalf("[-] Unknown group category: %s\n", group)
	}
	files, err := ioutil.ReadDir(filepath.Join(getCwdFromExe(), path))
	if err != nil {
		log.Fatalf("[-] Failed to list contents of %s folder\n", path)
	}
	var agentsOnDisk []string
	for _, f := range files {
		if f.IsDir() {
			agentsOnDisk = append(agentsOnDisk, f.Name())
		}
	}
	return agentsOnDisk
}
func status(){
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("[-] Failed to get client in status check: %v", err)
	}
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{
		All: true,
	})
	if err != nil {
		log.Fatalf("[-] Failed to get container list: %v", err)
	}
	printMythicConnectionInfo()
	if len(containers) > 0 {
		w := new(tabwriter.Writer)
		w.Init(os.Stdout, 0, 8, 2, '\t', 0)
		mythic_services := []string{}
		c2_services := []string{}
		payload_services := []string{}
		for _, container := range containers {
			if container.Labels["name"] == "" {
				continue
			}
			portRanges := []uint16{}
			portRangeMaps := []string{}
			info := fmt.Sprintf("%s\t%s\t%s\t", container.Labels["name"], container.State, container.Status)
			if len(container.Ports) > 0 {
				for _, port := range container.Ports {
					if port.PublicPort > 0 {
						if port.PrivatePort == port.PublicPort && port.IP == "0.0.0.0"{
							portRanges = append(portRanges, port.PrivatePort)
						}else{
							portRangeMaps = append(portRangeMaps, fmt.Sprintf("%d/%s -> %s:%d", port.PrivatePort, port.Type, port.IP, port.PublicPort))
						}
						
					}
				}
				if len(portRanges) > 0 {
					sort.Slice(portRanges, func(i, j int) bool {return portRanges[i] < portRanges[j] })
				}
				portString := strings.Join(portRangeMaps[:], ", ")
				var stringPortRanges []string 
				for _, val := range portRanges {
					stringPortRanges = append(stringPortRanges, fmt.Sprintf("%d", val))
				}
				if len(stringPortRanges) > 0  && len(portString) > 0{
					portString = portString + ", "
				}
				portString = portString + strings.Join(stringPortRanges[:], ", ")
				
				info = info + portString
			}
			if stringInSlice(container.Image, mythicServices) {
				mythic_services = append(mythic_services, info)
			}else{
				payloadAbsPath, err := filepath.Abs(filepath.Join(getCwdFromExe(), "Payload_Types"))
				if err != nil {
					fmt.Printf("[-] failed to get the absolute path to the Payload_Types folder")
					continue
				}
				c2AbsPath, err := filepath.Abs(filepath.Join(getCwdFromExe(), "C2_Profiles"))
				if err != nil {
					fmt.Printf("[-] failed to get the absolute path to the Payload_Types folder")
					continue
				}
				for _, mnt := range container.Mounts {
					if strings.HasPrefix(mnt.Source, payloadAbsPath) {
						payload_services = append(payload_services, info)
					} else if strings.HasPrefix(mnt.Source, c2AbsPath) {
						c2_services = append(c2_services, info)
					}
				}
			}
		}
		fmt.Printf("Mythic Main Services:\n")
		fmt.Fprintln(w, "NAME\tSTATE\tSTATUS\tPORTS")
		for _, line := range mythic_services {
			fmt.Fprintln(w, line)
		}
		w.Flush()
		fmt.Printf("\nPayload Type Services:\n")
		fmt.Fprintln(w, "NAME\tSTATE\tSTATUS\tPORTS")
		for _, line := range payload_services {
			fmt.Fprintln(w, line)
		}
		w.Flush()
		if len(payload_services) == 0 {
			containerList, err := getAllGroupNames("payload")
			if err != nil {
				log.Fatalf("[-] Failed to get all payload services: %v\n", err)
			}
			if len(containerList) > 0 {
				// there are c2 containers in the docker file
				containerTaskedToRunList := removeExclusionsFromSlice("payload", containerList)
				if len(containerTaskedToRunList) > 0 {
					// no containers are running, but there are ones that should be
					fmt.Printf("[-] No Payload Type containers are running, but the following should be running:\n    %v\n", containerTaskedToRunList)
					fmt.Printf("    Check the container status with \"sudo ./mythic-cli logs [container name]\" to check for errors\n")
					fmt.Printf("    To list all available C2_Profiles on disk and in docker-compose, run \"sudo ./mythic-cli c2 list\"\n")
				} else {
					// no containers are running and all available ones within the docker-compose file are excluded
					fmt.Printf("[*] All available Payload Type containers are included in an exclusion list!\n")
				}
			} else {
				// no containers are running and there are none in the docker-compose file
				files, err := ioutil.ReadDir(filepath.Join(getCwdFromExe(), "Payload_Types"))
				if err != nil {
					log.Fatalf("[-] Failed to list contents of %s folder\n", "Payload_Types")
				}
				var agentsOnDisk []string
				for _, f := range files {
					if f.IsDir() {
						agentsOnDisk = append(agentsOnDisk, f.Name())
					}
				}
				if len(agentsOnDisk) > 0{
					fmt.Printf("[*] There are no Payload Type containers installed; however, some do exist in the Payload_Types folder\n")
					fmt.Printf("    To install from the Payload_Types folder, run \"sudo ./mythic-cli payload add [agent name]\"\n")
					fmt.Printf("    To list all available Payload_Types on disk and in docker-compose, run \"sudo ./mythic-cli payload list\"\n")
				}else{
					fmt.Printf("[*] There are no Payload Type containers installed\n")
					fmt.Printf("    To install one, use \"sudo ./mythic-cli install github <url>\"\n")
					fmt.Printf("    Agents can be found at: https://github.com/MythicAgents\n")
				}
				
			}
			
		}
		fmt.Printf("\nC2 Profile Services:\n")
		fmt.Fprintln(w, "NAME\tSTATE\tSTATUS\tPORTS")
		for _, line := range c2_services {
			fmt.Fprintln(w, line)
		}
		w.Flush()
		if len(c2_services) == 0 {
			// no c2 containers are running, check to see if any are even installed
			containerList, err := getAllGroupNames("c2")
			if err != nil {
				log.Fatalf("[-] Failed to get all c2 services: %v\n", err)
			}
			if len(containerList) > 0 {
				// there are c2 containers in the docker file
				containerTaskedToRunList := removeExclusionsFromSlice("c2", containerList)
				if len(containerTaskedToRunList) > 0 {
					// no containers are running, but there are ones that should be
					fmt.Printf("[-] No C2 Profile containers are running, but the following should be running:\n    %v\n", containerTaskedToRunList)
					fmt.Printf("    Check the container status with \"sudo ./mythic-cli logs [container name]\" to check for errors\n")
				} else {
					// no containers are running and all available ones within the docker-compose file are excluded
					fmt.Printf("[*] All available C2 Profile containers are included in an exclusion list!\n")
				}
			} else {
				// no containers are running and there are none in the docker-compose file
				files, err := ioutil.ReadDir(filepath.Join(getCwdFromExe(), "C2_Profiles"))
				if err != nil {
					log.Fatalf("[-] Failed to list contents of %s folder\n", "C2_Profiles")
				}
				var agentsOnDisk []string
				for _, f := range files {
					if f.IsDir() {
						agentsOnDisk = append(agentsOnDisk, f.Name())
					}
				}
				if len(agentsOnDisk) > 0{
					fmt.Printf("[*] There are no C2 Profile containers installed; however, some do exist in the C2_Profiles folder\n")
					fmt.Printf("    To install from the C2_Profiles folder, run \"sudo ./mythic-cli c2 add [profile name]\"\n")
				}else{
					fmt.Printf("[*] There are no C2 Profile containers installed\n")
					fmt.Printf("    To install one, use \"sudo ./mythic-cli install github <url>\"\n")
					fmt.Printf("    C2 Profiles can be found at: https://github.com/MythicC2Profiles\n")
				}
			}
		}
	} else{
		fmt.Println("There are no containers running")
	}
	if mythicEnv.GetString("RABBITMQ_HOST") == "mythic_rabbitmq" && mythicEnv.GetBool("rabbitmq_bind_localhost_only"){
		fmt.Printf("\n[*] RabbitMQ is currently listening on localhost. If you have a remote PayloadType or C2Profile, they will be unable to connect")
		fmt.Printf("\n    Use 'sudo ./mythic-cli config set rabbitmq_bind_localhost_only false' and restart mythic ('sudo ./mythic-cli mythic start') to change this\n")
	}
	fmt.Printf("[*] If you are using a remote PayloadType or C2Profile, they will need certain environment variables to properly connect to Mythic.\n")
	fmt.Printf("    Use 'sudo ./mythic-cli config payload' or 'sudo ./mythic-cli config c2' for easy-to-use configs for these services.\n")
}
func logs(containerName string){
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Failed to get client in logs: %v", err)
	}
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		log.Fatalf("Failed to get container list: %v", err)
	}
	if len(containers) > 0 {
		for _, container := range containers {
			if container.Labels["name"] == containerName {
				reader, err := cli.ContainerLogs(context.Background(), container.ID, types.ContainerLogsOptions{
					ShowStdout: true,
					ShowStderr: true,
					Tail: "500",
				})
				if err != nil {
					log.Fatalf("Failed to get container logs: %v", err)
				}
				defer reader.Close()
				// awesome post about the leading 8 payload/header bytes: https://medium.com/@dhanushgopinath/reading-docker-container-logs-with-golang-docker-engine-api-702233fac044
				p := make([]byte, 8)
				_, err = reader.Read(p);
				for err == nil {
					content := make([]byte, binary.BigEndian.Uint32(p[4:]))
					reader.Read(content)
					fmt.Printf("%s", content)
					_, err = reader.Read(p);
				}
			}
		}
	} else{
		fmt.Println("Failed to find that container")
	}
}
func getMythicEnvList() []string {
	env := mythicEnv.AllSettings()
	var envList []string
	for key, _ := range env {
		val := mythicEnv.GetString(key)
		if val != "" {
			// prevent trying to append arrays or dictionaries to our environment list
			//fmt.Println(strings.ToUpper(key), val)
			envList = append(envList, strings.ToUpper(key) + "=" + val)
		}
	}
	return envList
}
func runDockerCompose(args []string) error{
	path, err := exec.LookPath("docker-compose")
	if err != nil {
		log.Fatalf("[-] docker-compose is not installed or not available in the current PATH variable")
	}
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("[-] Failed to get path to current executable")
	}
	exePath := filepath.Dir(exe)
	command := exec.Command(path, args...)
	command.Dir = exePath
	command.Env = getMythicEnvList()

	stdout, err := command.StdoutPipe()
	if err != nil {
		log.Fatalf("[-] Failed to get stdout pipe for running docker-compose")
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		log.Fatalf("[-] Failed to get stderr pipe for running docker-compose")
	}
	
	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)
	go func() {
		for stdoutScanner.Scan() {
            fmt.Printf("%s\n", stdoutScanner.Text())
        }
	}()
	go func() {
		for stderrScanner.Scan() {
            fmt.Printf("%s\n", stderrScanner.Text())
        }
	}()
	err = command.Start()
	if err != nil {
		log.Fatalf("[-] Error trying to start docker-compose: %v\n", err)
	}
	err = command.Wait()
	if err != nil {
		fmt.Printf("[-] Error from docker-compose: %v\n", err)
		return err
	}
	return nil
}
func getCwdFromExe() string {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("[-] Failed to get path to current executable")
	}
	return filepath.Dir(exe)
}
func runGitClone(args []string) error{
	path, err := exec.LookPath("git")
	if err != nil {
		fmt.Printf("[-] git is not installed or not available in the current PATH variable")
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("[-] Failed to get path to current executable")
		return err
	}
	exePath := filepath.Dir(exe)
	// git -c http.sslVerify=false clone --recurse-submodules --single-branch --branch $2 $1 temp

	command := exec.Command(path, args...)
	command.Dir = exePath
	command.Env = getMythicEnvList()

	stdout, err := command.StdoutPipe()
	if err != nil {
		fmt.Printf("[-] Failed to get stdout pipe for running git")
		return err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		fmt.Printf("[-] Failed to get stderr pipe for running git")
		return err
	}
	
	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)
	go func() {
		for stdoutScanner.Scan() {
            fmt.Printf("%s\n", stdoutScanner.Text())
        }
	}()
	go func() {
		for stderrScanner.Scan() {
            fmt.Printf("%s\n", stderrScanner.Text())
        }
	}()
	err = command.Start()
	if err != nil {
		fmt.Printf("[-] Error trying to start git: %v\n", err)
		return err
	}
	err = command.Wait()
	if err != nil {
		fmt.Printf("[-] Error trying to run git: %v\n", err)
		return err
	}
	return nil
}
func getAllGroupNames(group string) ([]string, error) {
	// given a group of {c2|payload}, get all of them that exist within the loaded config
	groupNameConfig := viper.New()
	groupNameConfig.SetConfigName("docker-compose")
	groupNameConfig.SetConfigType("yaml")
	groupNameConfig.AddConfigPath(getCwdFromExe())
	if err := groupNameConfig.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            fmt.Printf("[-] Error while reading in docker-compose file: %s", err)
            return []string{}, err
        } else {
            fmt.Printf("[-] Error while parsing docker-compose file: %s", err)
            return []string{}, err
        }
    }
	servicesSub := groupNameConfig.Sub("services")
	services := servicesSub.AllSettings()
	var absPath string
	var err error
	if group == "c2" {
		absPath, err = filepath.Abs(filepath.Join(getCwdFromExe(), "C2_Profiles"))
		if err != nil {
			fmt.Printf("[-] failed to get the absolute path to the C2_Profiles folder")
			return []string{}, err
		}
	}else if group == "payload" {
		absPath, err = filepath.Abs(filepath.Join(getCwdFromExe(), "Payload_Types"))
		if err != nil {
			fmt.Printf("[-] failed to get the absolute path to the C2_Profiles folder")
			return []string{}, err
		}
	}
	var containerList []string
	for container, _ := range services {
		build := servicesSub.GetString(container + ".build.context")
		if build == "" {
			build = servicesSub.GetString(container + ".build")
			if build == "" {
				log.Fatalf("[-] Failed to find the build path for %s\n", container)
			}
		}
		buildAbsPath, err := filepath.Abs(build)
		if err != nil {
			fmt.Printf("[-] failed to get the absolute path to the container's docker file")
			continue
		}
		if group == "mythic" {
			if stringInSlice(container, mythicServices) {
				containerList = append(containerList, container)
			}
		} else {
			if strings.HasPrefix(buildAbsPath, absPath) {
				// the service we're looking at has a build path that's a child of our folder, it should be a service
				containerList = append(containerList, container)
			}
		}
	}
	if group == "mythic" {
		// need to see about adding services back in if they were for remote hosts before
		for _, service := range mythicServices {
			if !stringInSlice(service, containerList){
				// service is a mythic service, but it's not in our current container list (i.e. not in docker-compose)
				switch service {
				case "mythic_react":
					if mythicEnv.GetString("MYTHIC_REACT_HOST") == "127.0.0.1" || mythicEnv.GetString("MYTHIC_REACT_HOST") == "mythic_react" {
						containerList = append(containerList, service)
					}
				case "mythic_nginx":
					if mythicEnv.GetString("MYTHIC_NGINX_HOST") == "127.0.0.1" || mythicEnv.GetString("MYTHIC_NGINX_HOST") == "mythic_nginx" {
						containerList = append(containerList, service)
					}
				case "mythic_rabbitmq":
					if mythicEnv.GetString("RABBITMQ_HOST") == "127.0.0.1" || mythicEnv.GetString("RABBITMQ_HOST") == "mythic_rabbitmq" {
						containerList = append(containerList, service)
					}
				case "mythic_redis":
					if mythicEnv.GetString("REDIS_HOST") == "127.0.0.1" || mythicEnv.GetString("REDIS_HOST") == "mythic_redis" {
						containerList = append(containerList, service)
					}
				case "mythic_server":
					if mythicEnv.GetString("MYTHIC_SERVER_HOST") == "127.0.0.1" || mythicEnv.GetString("MYTHIC_SERVER_HOST") == "mythic_server" {
						containerList = append(containerList, service)
					}
				case "mythic_postgres":
					if mythicEnv.GetString("POSTGRES_HOST") == "127.0.0.1" || mythicEnv.GetString("POSTGRES_HOST") == "mythic_postgres" {
						containerList = append(containerList, service)
					}
				}
			}
		}
	}
	return containerList, nil
}
func imageExists(containerName string) bool {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Failed to get client in logs: %v", err)
	}
	desiredImage := fmt.Sprintf("%v:latest", strings.ToLower(containerName))
	images, err := cli.ImageList(context.Background(), types.ImageListOptions{All: true})
	if err != nil {
		log.Fatalf("Failed to get container list: %v", err)
	}
	for _, image := range images {
		for _, name := range image.RepoTags {
			if name == desiredImage {
				return true
			}
		}
	}
	return false
}
func startStop(action string, group string, containerNameOriginals []string) error{
	// group is ["c2", "payload", "mythic"]
	// contianerName is a specific container or empty for all within a group
	containerNames := make([]string, 0)
	for _, val := range containerNameOriginals {
		containerNames = append(containerNames, strings.ToLower(val))
	}
    switch group {
    case "mythic":
    	// we're looking at the main mythic services here
		if action == "start" {
			writeMythicEnvironmentVariables()
			fmt.Printf("[+] Successfully updated configuration in .env\n")
			if len(containerNames) == 0{
				if mythicEnv.GetBool("REBUILD_ON_START"){
					runDockerCompose([]string{"down", "--volumes", "--remove-orphans"})
				}else{
					runDockerCompose([]string{"down", "--volumes"})
				}
				err := checkPorts()
				if err != nil {
					return err
				}
				c2ContainerList, err := getAllGroupNames("c2")
				if err != nil {
					fmt.Printf("[-] Failed to get all c2 services: %v\n", err)
					return err
				}
				payloadContainerList, err := getAllGroupNames("payload")
				if err != nil {
					fmt.Printf("[-] Failed to get all payload services: %v\n", err)
					return err
				}
				mythicContainerList, err := getAllGroupNames("mythic")
				if err != nil {
					fmt.Printf("[-] Failed to enumerate Mythic services: %v\n", err)
					return err
				}
				addRemoveDockerComposeEntries("add", "c2", c2ContainerList, make(map[string]interface{}), false, true)
				addRemoveDockerComposeEntries("add", "payload", payloadContainerList, make(map[string]interface{}), false, true)
				c2ContainerList = removeExclusionsFromSlice("c2", c2ContainerList)
				payloadContainerList = removeExclusionsFromSlice("payload", payloadContainerList)
				finalList := append(mythicContainerList, c2ContainerList...)
				finalList = append(finalList, payloadContainerList...)
				rabbitmqReset(false)
				
				if mythicEnv.GetBool("REBUILD_ON_START"){
					runDockerCompose(append([]string{"up", "--build", "-d"}, finalList...))
				}else{
					var needToBuild []string 
					var alreadyBuilt []string
					for _, val := range finalList {
						if !imageExists(val){
							needToBuild = append(needToBuild, val)
						}else{
							alreadyBuilt = append(alreadyBuilt, val)
						}
					}
					if len(needToBuild) > 0 {
						runDockerCompose(append([]string{"up", "--build", "-d"}, needToBuild...))
					}
					runDockerCompose(append([]string{"up", "-d"}, alreadyBuilt...))
				}
				testMythicRabbitmqConnection()
				testMythicConnection()
			} else {
				if mythicEnv.GetBool("REBUILD_ON_START"){
					runDockerCompose(append([]string{"up", "--build", "-d"}, containerNames...))
				} else{
					var needToBuild []string 
					var alreadyBuilt []string
					for _, val := range containerNames {
						if !imageExists(val){
							needToBuild = append(needToBuild, val)
						}else{
							alreadyBuilt = append(alreadyBuilt, val)
						}
					}
					if len(needToBuild) > 0 {
						runDockerCompose(append([]string{"up", "--build", "-d"}, needToBuild...))
					}
					runDockerCompose(append([]string{"up", "-d"}, alreadyBuilt...))
				}
				
			}
			status()
		}
		if action == "stop" {
			if len(containerNames) > 0 {
				runDockerCompose(append([]string{"rm", "-s", "-v", "-f"}, containerNames...))
				
			} else {
				if mythicEnv.GetBool("REBUILD_ON_START"){
					runDockerCompose(append([]string{"down", "--volumes", "--remove-orphans"}, containerNames...))
				}else{
					runDockerCompose(append([]string{"down", "--volumes"}, containerNames...))
				}
				
			}
		}
	case "c2":
		// we're looking at the c2 specific services
		if len(containerNames) == 0 {
			containerList, err := getAllGroupNames("c2")
			if err != nil {
				fmt.Printf("[-] Failed to get all c2 services: %v\n", err)
				return err
			}
			if len(containerList) == 0 {
				fmt.Printf("[*] No C2 Profiles currently registered. Try installing an agent or using the add subcommand\n")
				return nil
			}
			if action == "start" && len(containerList) > 0 {
				listWithoutExclusions := removeExclusionsFromSlice("c2", containerList)
				if len(listWithoutExclusions) == 0 {
					fmt.Printf("[*] All selected c2 profiles are in the exclusion list.\n")
					fmt.Printf("[*]   clear the list with: config set excluded_c2_profiles ''\n")
					return nil
				}
				if mythicEnv.GetBool("REBUILD_ON_START"){
					runDockerCompose(append([]string{"up", "--build", "-d"}, listWithoutExclusions...))
				}else{
					var needToBuild []string 
					var alreadyBuilt []string
					for _, val := range listWithoutExclusions {
						if !imageExists(val){
							needToBuild = append(needToBuild, val)
						}else{
							alreadyBuilt = append(alreadyBuilt, val)
						}
					}
					if len(needToBuild) > 0 {
						runDockerCompose(append([]string{"up", "--build", "-d"}, needToBuild...))
					}
					runDockerCompose(append([]string{"up", "-d"}, alreadyBuilt...))
				}
				testMythicRabbitmqConnection()
			} else if action == "stop" && len(containerList) > 0 {
				runDockerCompose(append([]string{"rm", "-s", "-v", "-f"}, containerList...))
			}
		}else{
			containerList, err := getAllGroupNames("c2")
			if err != nil {
				fmt.Printf("[-] Failed to get all c2 services: %v\n", err)
				return err
			}
			var finalList []string 
			diskAgents := getElementsOnDisk("c2")
			for _, val := range containerNames {
				if stringInSlice(val, containerList) {
					finalList = append(finalList, val)
				}else if stringInSlice(val, diskAgents){
					// the agent mentioned isn't in docker-compose, but is on disk, ask to add
					add := askConfirm(fmt.Sprintf("\n%s isn't in docker-compose, but is on disk. Would you like to add it? ", val))
					if add {
						err = addRemoveDockerComposeEntries("add", "c2", []string{val}, make(map[string]interface{}), false, true)
						if err != nil {
							log.Fatalf("[-] Failed to add %s to docker-compose: %v\n", val, err)
						}else{
							finalList = append(finalList, val)
						}
					}
				}else{
					add := askConfirm(fmt.Sprintf("\n%s isn't in docker-compose and is not on disk. Would you like to install it from https://github.com/MythicC2Profiles? ", val))
					if add {
						installAgent(fmt.Sprintf("https://github.com/MythicC2Profiles/%s", val), []string{"-f"})
						finalList = append(finalList, val)
					}
				}
			}
			runDockerCompose(append([]string{"rm", "-s", "-v", "-f"}, containerNames...))
			if action == "start" && len(containerNames) > 0 {
				if mythicEnv.GetBool("REBUILD_ON_START"){
					runDockerCompose(append([]string{"up", "--build", "-d"}, containerNames...))
				}else{
					var needToBuild []string 
					var alreadyBuilt []string
					for _, val := range containerNames {
						if !imageExists(val){
							needToBuild = append(needToBuild, val)
						}else{
							alreadyBuilt = append(alreadyBuilt, val)
						}
					}
					if len(needToBuild) > 0 {
						runDockerCompose(append([]string{"up", "--build", "-d"}, needToBuild...))
					}
					runDockerCompose(append([]string{"up", "-d"}, alreadyBuilt...))
				}
				testMythicRabbitmqConnection()
			}
		}
	case "payload":
		// we're looking at the payload type services
		if len(containerNames) == 0 {
			containerList, err := getAllGroupNames("payload")
			if err != nil {
				fmt.Printf("[-] Failed to get all payload services: %v\n", err)
				return err
			}
			if len(containerList) == 0 {
				fmt.Printf("[*] No Payloads currently registered. Try installing an agent or using the add subcommand\n")
				return nil
			}
			if action == "start" && len(containerList) > 0 {
				listWithoutExclusions := removeExclusionsFromSlice("payload", containerList)
				if len(listWithoutExclusions) == 0 {
					fmt.Printf("[*] All selected payloads are in the exclusion list.\n")
					fmt.Printf("[*]   clear the list with: config set excluded_payload_types ''\n")
					return nil
				}
				if mythicEnv.GetBool("REBUILD_ON_START"){
					runDockerCompose(append([]string{"up", "--build", "-d"}, listWithoutExclusions...))
				}else{
					var needToBuild []string 
					var alreadyBuilt []string
					for _, val := range listWithoutExclusions {
						if !imageExists(val){
							needToBuild = append(needToBuild, val)
						}else{
							alreadyBuilt = append(alreadyBuilt, val)
						}
					}
					if len(needToBuild) > 0 {
						runDockerCompose(append([]string{"up", "--build", "-d"}, needToBuild...))
					}
					runDockerCompose(append([]string{"up", "-d"}, alreadyBuilt...))
				}
				testMythicRabbitmqConnection()
			} else if action == "stop" && len(containerList) > 0 {
				runDockerCompose(append([]string{"rm", "-s", "-v", "-f"}, containerList...))
			}
		}else{
			containerList, err := getAllGroupNames("payload")
			if err != nil {
				fmt.Printf("[-] Failed to get all payload services: %v\n", err)
				return err
			}
			var finalList []string 
			diskAgents := getElementsOnDisk("payload")
			for _, val := range containerNames {
				if stringInSlice(val, containerList) {
					finalList = append(finalList, val)
				}else if stringInSlice(val, diskAgents){
					// the agent mentioned isn't in docker-compose, but is on disk, ask to add
					add := askConfirm(fmt.Sprintf("\n%s isn't in docker-compose, but is on disk. Would you like to add it? ", val))
					if add {
						err = addRemoveDockerComposeEntries("add", "payload", []string{val}, make(map[string]interface{}), false, true)
						if err != nil {
							log.Fatalf("[-] Failed to add %s to docker-compose: %v\n", val, err)
						}else{
							finalList = append(finalList, val)
						}
					}
				}else{
					add := askConfirm("\n%s isn't in docker-compose and is not on disk. Would you like to install it from https://github.com/MythicAgents? ")
					if add {
						installAgent(fmt.Sprintf("https://github.com/MythicAgents/%s", val), []string{"-f"})
						finalList = append(finalList, val)
					}
				}
			}
			if len(finalList) == 0 {
				// none of the agents that the user indicated are in docker-compose, aren't installed, and aren't on disk
				log.Fatalf("[-] No agents available to start\n")
			}
			runDockerCompose(append([]string{"rm", "-s", "-v", "-f"}, containerNames...))
			
			if action == "start" && len(containerNames) > 0 {
				if mythicEnv.GetBool("REBUILD_ON_START"){
					runDockerCompose(append([]string{"up", "--build", "-d"}, containerNames...))
				}else{
					var needToBuild []string 
					var alreadyBuilt []string
					for _, val := range containerNames {
						if !imageExists(val){
							needToBuild = append(needToBuild, val)
						}else{
							alreadyBuilt = append(alreadyBuilt, val)
						}
					}
					if len(needToBuild) > 0 {
						runDockerCompose(append([]string{"up", "--build", "-d"}, needToBuild...))
					}
					runDockerCompose(append([]string{"up", "-d"}, alreadyBuilt...))
				}
				testMythicRabbitmqConnection()
			}
		}
	default:
		fmt.Printf("[-] Unknown group for starting container\n")
		return nil
    }
    return nil
}
// https://golangcode.com/check-if-a-file-exists/
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err){
			return false;
		}
	}
	return !info.IsDir()
}
// https://golangcode.com/check-if-a-file-exists/
func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err){
			return false;
		}
	}
	return info.IsDir()
}
// https://blog.depa.do/post/copy-files-and-directories-in-go
func copyFile(src, dst string) error {
	var err error
	var srcfd *os.File
	var dstfd *os.File
	var srcinfo os.FileInfo

	if srcfd, err = os.Open(src); err != nil {
		return err
	}
	defer srcfd.Close()

	if dstfd, err = os.Create(dst); err != nil {
		return err
	}
	defer dstfd.Close()

	if _, err = io.Copy(dstfd, srcfd); err != nil {
		return err
	}
	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}
	return os.Chmod(dst, srcinfo.Mode())
}
// https://blog.depa.do/post/copy-files-and-directories-in-go
func copyDir(src string, dst string) error {
	var err error
	var fds []os.FileInfo
	var srcinfo os.FileInfo

	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}

	if err = os.MkdirAll(dst, srcinfo.Mode()); err != nil {
		return err
	}

	if fds, err = ioutil.ReadDir(src); err != nil {
		return err
	}
	for _, fd := range fds {
		srcfp := path.Join(src, fd.Name())
		dstfp := path.Join(dst, fd.Name())

		if fd.IsDir() {
			if err = copyDir(srcfp, dstfp); err != nil {
				fmt.Println(err)
			}
		} else {
			if err = copyFile(srcfp, dstfp); err != nil {
				fmt.Println(err)
			}
		}
	}
	return nil
}
// https://gist.github.com/r0l1/3dcbb0c8f6cfe9c66ab8008f55f8f28b
func askConfirm(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s [y/n]: ", prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("[-] Failed to read user input\n")
			return false
		}
		input = strings.ToLower(strings.TrimSpace(input))
		if input == "y" || input == "yes" {
			return true
		}else if input == "n" || input == "no" {
			return false
		}
	}
}
// https://gist.github.com/r0l1/3dcbb0c8f6cfe9c66ab8008f55f8f28b
func askVariable(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s: ", prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("[-] Failed to read user input\n")
			return ""
		}
		input = strings.TrimSpace(input)
		return input
	}
}
func getBuildArguments() []string {
	var buildEnv = viper.New()
	buildEnv.SetConfigName("build.env")
    buildEnv.SetConfigType("env")
    buildEnv.AddConfigPath(getCwdFromExe())
    buildEnv.AutomaticEnv()
    if !fileExists(filepath.Join(getCwdFromExe(), "build.env")) {
    	fmt.Printf("[*] No build.env file detected in Mythic's root directory; not supplying build arguments to docker containers\n")
    	fmt.Printf("    If you need to supply build arguments to docker containers, create build.env and supply key=value entries there\n")
    	return []string{}
    }
    if err := buildEnv.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            log.Fatalf("[-] Error while reading in build.env file: %s", err)
        } else {
            log.Fatalf("[-]Error while parsing build.env file: %s", err)
        }
    }
    c := buildEnv.AllSettings()
    // to make it easier to read and look at, get all the keys, sort them, and display variables in order
    keys := make([]string, 0, len(c))
    for k := range c {
    	keys = append(keys, k)
    }
    sort.Strings(keys)
    var args []string
    for _, key := range keys {
    	args = append( args, fmt.Sprintf("%s=%s", strings.ToUpper(key), buildEnv.GetString(key)) )
    }
    return args
}
func addRemoveMythicServiceDockerEntries(action string, names []string) {
	var curConfig = viper.New()
	curConfig.SetConfigName("docker-compose")
	curConfig.SetConfigType("yaml")
	curConfig.AddConfigPath(getCwdFromExe())
	if err := curConfig.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            log.Fatalf("[-] Error while reading in docker-compose file: %s\n", err)
        } else {
            log.Fatalf("[-] Error while parsing docker-compose file: %s\n", err)
        }
    }
    network_info := map[string]interface{}{
		"default_network": map[string]interface{}{
			"driver": "bridge",
			"driver_opts": map[string]string{
				"com.docker.network.bridge.name": "mythic_if",
			},
			"ipam": map[string]interface{}{
				"config": []map[string]interface{}{
					map[string]interface{}{
						"subnet": "172.100.0.0/16",
					},
					
				},
				"driver": "default",
			},
			"labels": []string{
				"mythic_network",
				"default_network",
			},
		},
    }
    curConfig.Set("networks", network_info)
    for _, service := range names {
    	if action == "remove" {
    		if isServiceRunning(service){
				startStop("stop", "mythic", []string{strings.ToLower(service)})
			}
			if curConfig.IsSet("services." + strings.ToLower(service)) {
				delete(curConfig.Get("services").(map[string]interface{}), strings.ToLower(service))
				fmt.Printf("[+] Removed %s from docker-compose because it's running on a different host\n", strings.ToLower(service))
			}
			var updatedMythicServices []string 
			for _, val := range mythicServices {
				if val != service {
					updatedMythicServices = append(updatedMythicServices, val)
				}
			}
			mythicServices = updatedMythicServices
			
    	}else{
    		// adding or setting services in the docker-compose file
    		var pStruct map[string]interface{}
    		
    		if curConfig.IsSet("services." + strings.ToLower(service)) {
	    		pStruct = curConfig.GetStringMap("services." + strings.ToLower(service))
	    		delete(pStruct, "network_mode")
	    		delete(pStruct, "extra_hosts")
	    		delete(pStruct, "build")
	    		pStruct["networks"] = []string{
	    			"default_network",
	    		}
    		}else{
    			pStruct = map[string]interface{}{
	    			"logging": map[string]interface{}{
		    			"driver": "json-file",
		    			"options": map[string]string{
		    				"max-file": "1",
		    				"max-size": "10m",
		    			},
		    		},
		    		"restart": "always",
		    		"labels": map[string]string{
		    			"name": service,
		    		},
		    		"container_name": service,
		    		"image": service,
		    		"networks": []string{
		    			"default_network",
		    		},
		    	}
    		}
    		
    		switch service {
    		case "mythic_postgres":
    			pStruct["build"] = map[string]interface{}{
    				"context": "./postgres-docker",
    				"args": buildArguments,
				}
    			pStruct["command"] = "postgres -c \"max_connections=400\" -p ${POSTGRES_PORT}"
    			pStruct["volumes"] = []string{
    				"./postgres-docker/database:/var/lib/postgresql/data",
    			}
    			if mythicEnv.GetBool("postgres_bind_localhost_only"){
    				pStruct["ports"] = []string{
	    				"127.0.0.1:${POSTGRES_PORT}:${POSTGRES_PORT}",
	    			}
    			}else{
    				pStruct["ports"] = []string{
    					"${POSTGRES_PORT}:${POSTGRES_PORT}",
    				}
    			}
    			environment := []string{
	    			"POSTGRES_DB=${POSTGRES_DB}",
					"POSTGRES_USER=${POSTGRES_USER}",
					"POSTGRES_PASSWORD=${POSTGRES_PASSWORD}",
	    		}
    			if _, ok := pStruct["environment"]; ok {
    				pStruct["environment"] = updateEnvironmentVariables(curConfig.GetStringSlice("services." + strings.ToLower(service) + ".environment"), environment)
    			}else{
    				pStruct["environment"] = environment
    			}
	    	case "mythic_documentation":
	    		pStruct["build"] = "./documentation-docker"
	    		pStruct["build"] = map[string]interface{}{
    				"context": "./documentation-docker",
    				"args": buildArguments,
				}
	    		pStruct["command"] = "server -p ${DOCUMENTATION_PORT}"
	    		if mythicEnv.GetBool("documentation_bind_localhost_only"){
	    			pStruct["ports"] = []string{
		    			"127.0.0.1:${DOCUMENTATION_PORT}:${DOCUMENTATION_PORT}",
		    		}
	    		}else{
	    			pStruct["ports"] = []string{
		    			"${DOCUMENTATION_PORT}:${DOCUMENTATION_PORT}",
		    		}
	    		}
	    		
	    		pStruct["volumes"] = []string{
	    			"./documentation-docker/:/src",
	    		}
	    	case "mythic_graphql":
	    		pStruct["build"] = map[string]interface{}{
    				"context": "./hasura-docker",
    				"args": buildArguments,
				}
	    		environment := []string{
	    			"HASURA_GRAPHQL_DATABASE_URL=postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}",
    				"HASURA_GRAPHQL_METADATA_DATABASE_URL=postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}",
    				"HASURA_GRAPHQL_ENABLE_CONSOLE=true",
    				"HASURA_GRAPHQL_DEV_MODE=false",
    				"HASURA_GRAPHQL_ADMIN_SECRET=${HASURA_SECRET}",
    				"HASURA_GRAPHQL_INSECURE_SKIP_TLS_VERIFY=true",
    				"HASURA_GRAPHQL_SERVER_PORT=${HASURA_PORT}",
    				"HASURA_GRAPHQL_METADATA_DIR=/metadata",
    				"HASURA_GRAPHQL_LIVE_QUERIES_MULTIPLEXED_REFETCH_INTERVAL=1000",
    				"HASURA_GRAPHQL_AUTH_HOOK=http://${MYTHIC_SERVER_HOST}:${MYTHIC_SERVER_PORT}/graphql/webhook",
    				"MYTHIC_ACTIONS_URL_BASE=http://${MYTHIC_SERVER_HOST}:${MYTHIC_SERVER_PORT}/api/v1.4",
	    		}
	    		if _, ok := pStruct["environment"]; ok {
    				pStruct["environment"] = updateEnvironmentVariables(curConfig.GetStringSlice("services." + strings.ToLower(service) + ".environment"), environment)
    			}else{
    				pStruct["environment"] = environment
    			}
	    		pStruct["volumes"] = []string{
	    			"./hasura-docker/metadata:/metadata",
	    		}
	    		if mythicEnv.GetBool("hasura_bind_localhost_only"){
	    			pStruct["ports"] = []string{
		    			"127.0.0.1:${HASURA_PORT}:${HASURA_PORT}",
		    		}
	    		}else{
	    			pStruct["ports"] = []string{
		    			"${HASURA_PORT}:${HASURA_PORT}",
		    		}
	    		}
	    	case "mythic_nginx":
	    		pStruct["build"] = map[string]interface{}{
    				"context": "./nginx-docker",
    				"args": buildArguments,
				}
				nginxUseSSL := "ssl"
				if !mythicEnv.GetBool("NGINX_USE_SSL") {
					nginxUseSSL = ""
				}
	    		environment := []string{
	    			"DOCUMENTATION_HOST=${DOCUMENTATION_HOST}",
    				"DOCUMENTATION_PORT=${DOCUMENTATION_PORT}",
    				"NGINX_PORT=${NGINX_PORT}",
    				"MYTHIC_SERVER_HOST=${MYTHIC_SERVER_HOST}",
    				"MYTHIC_SERVER_PORT=${MYTHIC_SERVER_PORT}",
    				"HASURA_HOST=${HASURA_HOST}",
    				"HASURA_PORT=${HASURA_PORT}",
    				"MYTHIC_REACT_HOST=${MYTHIC_REACT_HOST}",
    				"MYTHIC_REACT_PORT=${MYTHIC_REACT_PORT}",
    				fmt.Sprintf("NGINX_USE_SSL=%s", nginxUseSSL),
	    		}
	    		if _, ok := pStruct["environment"]; ok {
    				environment = updateEnvironmentVariables(curConfig.GetStringSlice("services." + strings.ToLower(service) + ".environment"), environment)
    			}
    			var finalNginxEnv []string
    			for _, val := range environment {
    				if !strings.Contains(val, "NEW_UI") {
    					finalNginxEnv = append(finalNginxEnv, val)
    				}
    			}
    			pStruct["environment"] = finalNginxEnv
	    		pStruct["volumes"] = []string{
	    			"./nginx-docker/ssl:/etc/ssl/private",
	    			"./nginx-docker/config:/etc/nginx",
	    		}
	    		if mythicEnv.GetBool("nginx_bind_localhost_only"){
	    			pStruct["ports"] = []string{
		    			"127.0.0.1:${NGINX_PORT}:${NGINX_PORT}",
		    		}
	    		}else{
	    			pStruct["ports"] = []string{
		    			"${NGINX_PORT}:${NGINX_PORT}",
		    		}
	    		}
	    	case "mythic_rabbitmq":
	    		pStruct["build"] = map[string]interface{}{
    				"context": "./rabbitmq-docker",
    				"args": buildArguments,
				}
	    		pStruct["command"] = "/bin/sh -c \"chmod +x /generate_config.sh && /generate_config.sh && rabbitmq-server\""
	    		if mythicEnv.GetBool("rabbitmq_bind_localhost_only"){
	    			pStruct["ports"] = []string{
		    			"127.0.0.1:${RABBITMQ_PORT}:${RABBITMQ_PORT}",
		    		}
	    		}else{
	    			pStruct["ports"] = []string{
		    			"${RABBITMQ_PORT}:${RABBITMQ_PORT}",
		    		}
	    		}
	    		environment := []string{
	    			"RABBITMQ_USER=${RABBITMQ_USER}",
    				"RABBITMQ_PASSWORD=${RABBITMQ_PASSWORD}",
    				"RABBITMQ_VHOST=${RABBITMQ_VHOST}",
    				"RABBITMQ_PORT=${RABBITMQ_PORT}",
	    		}
	    		if _, ok := pStruct["environment"]; ok {
    				environment = updateEnvironmentVariables(curConfig.GetStringSlice("services." + strings.ToLower(service) + ".environment"), environment)
    			}
    			var finalRabbitEnv []string 
    			badRabbitMqEnvs := []string{
    				"RABBITMQ_DEFAULT_USER=${RABBITMQ_USER}",
    				"RABBITMQ_DEFAULT_PASS=${RABBITMQ_PASSWORD}",
    				"RABBITMQ_DEFAULT_VHOST=${RABBITMQ_VHOST}",
    			}
    			for _, val := range environment {
    				if !stringInSlice(val, badRabbitMqEnvs) {
    					finalRabbitEnv = append(finalRabbitEnv, val)
    				}
    			}
    			pStruct["environment"] = finalRabbitEnv
	    		pStruct["volumes"] = []string{
	    			"./rabbitmq-docker/storage:/var/lib/rabbitmq",
	    			"./rabbitmq-docker/generate_config.sh:/generate_config.sh",
	    			"./rabbitmq-docker/rabbitmq.conf:/tmp/base_rabbitmq.conf",
	    		}
	    	case "mythic_react":
	    		pStruct["build"] = map[string]interface{}{
    				"context": "./mythic-react-docker",
    				"args": buildArguments,
				}
	    		if mythicEnv.GetBool("mythic_react_bind_localhost_only"){
	    			pStruct["ports"] = []string{
		    			"127.0.0.1:${MYTHIC_REACT_PORT}:${MYTHIC_REACT_PORT}",
		    		}
	    		}else{
    				pStruct["ports"] = []string{
		    			"${MYTHIC_REACT_PORT}:${MYTHIC_REACT_PORT}",
		    		}
	    		}
	    		pStruct["volumes"] = []string{
	    			"./mythic-react-docker/config:/etc/nginx",
	    			"./mythic-react-docker/mythic/public:/mythic/new",
	    		}
	    		pStruct["environment"] = []string{
	    			"MYTHIC_REACT_PORT=${MYTHIC_REACT_PORT}",
	    		}
	    	case "mythic_redis":
	    		pStruct["build"] = map[string]interface{}{
    				"context": "./redis-docker",
    				"args": buildArguments,
				}
	    		pStruct["command"] = "--port ${REDIS_PORT}"
	    		if mythicEnv.GetBool("redis_bind_localhost_only"){
	    			pStruct["ports"] = []string{
		    			"127.0.0.1:${REDIS_PORT}:${REDIS_PORT}",
		    		}
	    		}else{
	    			pStruct["ports"] = []string{
		    			"${REDIS_PORT}:${REDIS_PORT}",
		    		}
	    		}
	    	case "mythic_server":
	    		pStruct["build"] = map[string]interface{}{
    				"context": "./mythic-docker",
    				"args": buildArguments,
				}
	    		pStruct["command"] = "/bin/bash /Mythic/start_mythic_server.sh"
	    		pStruct["volumes"] = []string{
	    			"./mythic-docker:/Mythic",
	    		}
	    		environment := []string{
	    			"MYTHIC_POSTGRES_HOST=${POSTGRES_HOST}",
	    			"MYTHIC_POSTGRES_PORT=${POSTGRES_PORT}",
	    			"MYTHIC_POSTGRES_DB=${POSTGRES_DB}",
	    			"MYTHIC_POSTGRES_USER=${POSTGRES_USER}",
	    			"MYTHIC_POSTGRES_PASSWORD=${POSTGRES_PASSWORD}",
	    			"MYTHIC_RABBITMQ_HOST=${RABBITMQ_HOST}",
	    			"MYTHIC_RABBITMQ_PORT=${RABBITMQ_PORT}",
	    			"MYTHIC_RABBITMQ_USER=${RABBITMQ_USER}",
	    			"MYTHIC_RABBITMQ_PASSWORD=${RABBITMQ_PASSWORD}",
	    			"MYTHIC_RABBITMQ_VHOST=${RABBITMQ_VHOST}",
	    			"MYTHIC_JWT_SECRET=${JWT_SECRET}",
	    			"MYTHIC_REDIS_PORT=${REDIS_PORT}",
	    			"MYTHIC_REDIS_HOST=${REDIS_HOST}",
	    			"MYTHIC_DEBUG=${MYTHIC_DEBUG}",
	    			"MYTHIC_ADMIN_PASSWORD=${MYTHIC_ADMIN_PASSWORD}",
	    			"MYTHIC_ADMIN_USER=${MYTHIC_ADMIN_USER}",
	    			"MYTHIC_SERVER_PORT=${MYTHIC_SERVER_PORT}",
	    			"MYTHIC_ALLOWED_IP_BLOCKS=${ALLOWED_IP_BLOCKS}",
	    			"MYTHIC_DEFAULT_OPERATION_NAME=${DEFAULT_OPERATION_NAME}",
	    			"MYTHIC_NGINX_PORT=${NGINX_PORT}",
	    			"MYTHIC_NGINX_HOST=${NGINX_HOST}",
	    			"MYTHIC_SERVER_HEADER=${SERVER_HEADER}",
	    			"MYTHIC_WEB_LOG_SIZE=${WEB_LOG_SIZE}",
	    			"MYTHIC_WEB_KEEP_LOGS=${WEB_KEEP_LOGS}",
	    			"MYTHIC_SIEM_LOG_NAME=${SIEM_LOG_NAME}",
	    			"MYTHIC_SERVER_DYNAMIC_PORTS=${MYTHIC_SERVER_DYNAMIC_PORTS}",
	    		}
	    		mythicServerPorts := []string{
	    			"${MYTHIC_SERVER_PORT}:${MYTHIC_SERVER_PORT}",
	    		}
	    		if mythicEnv.GetBool("MYTHIC_SERVER_BIND_LOCALHOST_ONLY"){
	    			mythicServerPorts = []string{
		    			"127.0.0.1:${MYTHIC_SERVER_PORT}:${MYTHIC_SERVER_PORT}",
		    		}
	    		}
	    		dynamicPortPieces := strings.Split(mythicEnv.GetString("MYTHIC_SERVER_DYNAMIC_PORTS"), ",")
	    		for _, val := range dynamicPortPieces {
	    			mythicServerPorts = append(mythicServerPorts, fmt.Sprintf("%s:%s", val, val))
	    		}
	    		pStruct["ports"] = mythicServerPorts
	    		if _, ok := pStruct["environment"]; ok {
    				pStruct["environment"] = updateEnvironmentVariables(curConfig.GetStringSlice("services." + strings.ToLower(service) + ".environment"), environment)
    			}else{
    				pStruct["environment"] = environment
    			}
    		}
    		if !curConfig.IsSet("services." + strings.ToLower(service)) {
    			curConfig.Set("services." + strings.ToLower(service), pStruct)
				fmt.Printf("[+] Added %s to docker-compose\n", strings.ToLower(service))
    		}else{
    			curConfig.Set("services." + strings.ToLower(service), pStruct)
    		}
    	}
    }
    curConfig.Set("networks", network_info)
	curConfig.WriteConfig()
}
func addRemoveDockerComposeEntries(action string, group string, names []string, additionalConfigs map[string]interface{}, isUninstall bool, update bool) error {
	// add c2/payload [name] as type [group] to the main yaml file
	var curConfig = viper.New()
	curConfig.SetConfigName("docker-compose")
	curConfig.SetConfigType("yaml")
	curConfig.AddConfigPath(getCwdFromExe())
	if err := curConfig.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            log.Fatalf("[-] Error while reading in docker-compose file: %s", err)
        } else {
            log.Fatalf("[-] Error while parsing docker-compose file: %s", err)
        }
    }
    network_info := map[string]interface{}{
		"default_network": map[string]interface{}{
			"driver": "bridge",
			"driver_opts": map[string]string{
				"com.docker.network.bridge.name": "mythic_if",
			},
			"ipam": map[string]interface{}{
				"config": []map[string]interface{}{
					map[string]interface{}{
						"subnet": "172.100.0.0/16",
					},
					
				},
				"driver": "default",
			},
			"labels": []string{
				"mythic_network",
				"default_network",
			},
		},
    }
    curConfig.Set("networks", network_info)
    for _, payload := range names {
    	if action == "add" {
    		var absPath string
    		var err error
    		var pStruct map[string]interface{}
    		if group == "payload" {
	    		absPath, err = filepath.Abs(filepath.Join(getCwdFromExe(), "Payload_Types", payload))
				if err != nil {
					fmt.Printf("[-] Failed to get the absolute path to the Payload_Types folder, does the agent folder exist?")
					fmt.Printf("[*] If the payload doesn't exist, you might need to install with 'mythic-cli install'")
					os.Exit(1)
				}
	    	} else if group == "c2" {
	    		absPath, err = filepath.Abs(filepath.Join(getCwdFromExe(), "C2_Profiles", payload))
				if err != nil {
					fmt.Printf("[-] Failed to get the absolute path to the C2_Profiles folder, does the c2 profile folder exist?")
					fmt.Printf("[*] If the profile doesn't exist on disk, you might need to install with 'mythic-cli install'")
					os.Exit(1)
				}
	    	}
	    	if !dirExists(absPath) {
	    		fmt.Printf("[-] %s does not exist, not adding to Mythic\n", absPath)
	    		os.Exit(1)
	    	}
	    	if curConfig.IsSet("services." + strings.ToLower(payload)) {
	    		pStruct = curConfig.GetStringMap("services." + strings.ToLower(payload))
	    		delete(pStruct, "network_mode")
	    		pStruct["image"] = strings.ToLower(payload)
	    		pStruct["networks"] = []string{
	    			"default_network",
	    		}
	    	}else{
	    		pStruct = map[string]interface{}{
		    		"labels": map[string]string{
		    			"name": payload,
		    		},
		    		"image": strings.ToLower(payload),
		    		"hostname": payload,
		    		"logging": map[string]interface{}{
		    			"driver": "json-file",
		    			"options": map[string]string{
		    				"max-file": "1",
		    				"max-size": "10m",
		    			},
		    		},
		    		"restart": "always",
		    		"volumes": []string{
		    			absPath + ":/Mythic/",
		    		},
		    		"networks": []string{
		    			"default_network",
		    		},
		    	}
	    	}
	    	for key, element := range additionalConfigs {
	    		pStruct[key] = element
	    	}
	    	pStruct["build"] = map[string]interface{}{
				"context": absPath,
				"args": buildArguments,
			}
	    	environment := []string{
    			"MYTHIC_ADDRESS=http://${MYTHIC_SERVER_HOST}:${MYTHIC_SERVER_PORT}/api/v1.4/agent_message",
				"MYTHIC_WEBSOCKET=ws://${MYTHIC_SERVER_HOST}:${MYTHIC_SERVER_PORT}/ws/agent_message",
				"MYTHIC_USERNAME=${RABBITMQ_USER}",
				"MYTHIC_PASSWORD=${RABBITMQ_PASSWORD}",
				"MYTHIC_VIRTUAL_HOST=${RABBITMQ_VHOST}",
				"MYTHIC_HOST=${RABBITMQ_HOST}",
				"MYTHIC_PORT=${RABBITMQ_PORT}",
				"MYTHIC_ENVIRONMENT=${MYTHIC_ENVIRONMENT}",
    		}
	    	if _, ok := pStruct["environment"]; ok {
				pStruct["environment"] = updateEnvironmentVariables(curConfig.GetStringSlice("services." + strings.ToLower(payload) + ".environment"), environment)
			}else{
				pStruct["environment"] = environment
			}
	    	if group == "c2" {
	    		pStruct["network_mode"] = "host"
	    		pStruct["extra_hosts"] = []string{
	    			"mythic_server:127.0.0.1",
    				"mythic_rabbitmq:127.0.0.1",
	    		}
	    		delete(pStruct, "networks")
	    	}
	    	curConfig.Set("networks", network_info)
			curConfig.Set("services." + strings.ToLower(payload), pStruct)
			curConfig.WriteConfig()
			if !update {
				fmt.Println("[+] Successfully updated docker-compose.yml")
				if isServiceRunning("mythic_server"){
					startStop("start", group, []string{strings.ToLower(payload)})
				}
			}
			
    	}else if action == "remove" {
			if !stringInSlice(payload, mythicServices) {
				if isServiceRunning(payload){
					startStop("stop", group, []string{strings.ToLower(payload)})
				}
				delete(curConfig.Get("services").(map[string]interface{}), strings.ToLower(payload))
				if !isUninstall {
					fmt.Printf("[+] Removed %s from docker-compose, but files are still on disk. \nTo remove from disk use 'mythic-cli uninstall %s'\n", strings.ToLower(payload), strings.ToLower(payload))
				}else{
					fmt.Printf("[+] Removed %s from docker-compose\n", strings.ToLower(payload))
				}
			}
			curConfig.WriteConfig()
			fmt.Println("[+] Successfully updated docker-compose.yml")
		}
    }
    curConfig.Set("networks", network_info)
	curConfig.WriteConfig()
	return nil
}
func installFolder(installPath string, args []string) error {
	workingPath := getCwdFromExe()
	overWrite := false
	if len(args) > 0 {
		if args[0] == "-f" {
			overWrite = true
		}
	}
	if fileExists(filepath.Join(installPath, "config.json")){
		var config = viper.New()
		config.SetConfigName("config")
	    config.SetConfigType("json")
	    fmt.Printf("[*] Parsing config.json\n")
	    config.AddConfigPath(installPath)
	    if err := config.ReadInConfig(); err != nil {
	        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
	            fmt.Printf("[-] Error while reading in config file: %s", err)
	            return err
	        } else {
	            fmt.Printf("[-] Error while parsing config file: %s", err)
	            return err
	        }
	    }
	    if !config.GetBool("exclude_payload_type") {
	    	// handle the payload type copying here
	    	files, err := ioutil.ReadDir(filepath.Join(installPath, "Payload_Type"))
	    	if err != nil {
	    		fmt.Printf("[-] Failed to list contents of new Payload_Type folder: %v\n", err)
	    		return err
	    	}
	    	for _, f := range files {
	    		if f.IsDir() {
	    			fmt.Printf("[*] Processing Payload Type %s\n", f.Name())
	    			if dirExists(filepath.Join(workingPath, "Payload_Types", f.Name())) {
	    				if overWrite || askConfirm("[*] " + f.Name() + " already exists. Replace current version? "){
	    					fmt.Printf("[*] Stopping current container\n")
	    					if isServiceRunning(strings.ToLower(f.Name())){
	    						startStop("stop", "payload", []string{f.Name()})
	    					}
	    					fmt.Printf("[*] Removing current version\n")
	    					err = os.RemoveAll(filepath.Join(workingPath, "Payload_Types", f.Name()))
	    					if err != nil {
	    						fmt.Printf("[-] Failed to remove current version: %v\n", err)
	    						fmt.Printf("[-] Continuing to the next payload\n")
    							continue
	    					}else{
	    						fmt.Printf("[+] Successfully removed the current version\n")
	    					}
	    				}else{
	    					fmt.Printf("[!] Skipping Payload Type, %s\n", f.Name())
	    					continue
	    				}
	    			}
	    			fmt.Printf("[*] Copying new version of payload into place\n")
	    			err = copyDir(filepath.Join(installPath, "Payload_Type", f.Name()), filepath.Join(workingPath, "Payload_Types", f.Name()))
	    			if err != nil {
	    				fmt.Printf("[-] Failed to copy directory over: %v\n", err)
	    				continue
	    			}
	    			// need to make sure the payload_service.sh file is executable
	    			if fileExists(filepath.Join(workingPath, "Payload_Types", f.Name(), "mythic", "payload_service.sh")) {
	    				err = os.Chmod(filepath.Join(workingPath, "Payload_Types", f.Name(), "mythic", "payload_service.sh"), 0777)
	    				if err != nil {
	    					fmt.Printf("[-] Failed to make payload_service.sh file executable\n")
	    					continue
	    				}
	    			} else if fileExists(filepath.Join(workingPath, "Payload_Types", f.Name(), "mythic", "c2_service.sh")){
	    				// this is the case where we have a translation container that was bundled with the Payload being installed
	    				err = os.Chmod(filepath.Join(workingPath, "Payload_Types", f.Name(), "mythic", "c2_service.sh"), 0777)
	    				if err != nil {
	    					fmt.Printf("[-] Failed to make c2_service.sh file executable\n")
	    					continue
	    				}
	    			} else {
	    				fmt.Printf("[-] failed to find payload_service.sh or c2_service.sh file for %s\n", f.Name())
	    				continue
	    			}
	    			//find ./Payload_Types/ -name "payload_service.sh" -exec chmod +x {} \;
	    			// now add payload type to yaml config
	    			fmt.Printf("[*] Adding payload into docker-compose\n")
	    			if config.IsSet("docker-compose"){
	    				addRemoveDockerComposeEntries("add", "payload", []string{f.Name()}, config.GetStringMap("docker-compose"), false, false)
	    			}else{
	    				addRemoveDockerComposeEntries("add", "payload", []string{f.Name()}, make(map[string]interface{}), false, false)
	    			}
    				
	    		}
	    	}
	    	fmt.Printf("[+] Successfully installed agent\n")
	    }else{
	    	fmt.Printf("[*] Skipping over Payload Type\n")
	    }
	    if !config.GetBool("exclude_c2_profiles") {
	    	// handle the c2 profile copying here
	    	files, err := ioutil.ReadDir(filepath.Join(installPath, "C2_Profiles"))
	    	if err != nil {
	    		fmt.Printf("[-] Failed to list contents of C2_Profiles folder from clone\n")
	    		return err
	    	}
	    	for _, f := range files {
	    		if f.IsDir() {
	    			fmt.Printf("[*] Processing C2 Profile %s\n", f.Name())
	    			if dirExists(filepath.Join(workingPath, "C2_Profiles", f.Name())) {
	    				if overWrite || askConfirm("[*] " + f.Name() + " already exists. Replace current version? "){
	    					fmt.Printf("[*] Stopping current container\n")
	    					if isServiceRunning(strings.ToLower(f.Name())){
	    						startStop("stop", "c2", []string{f.Name()})
	    					}
	    					fmt.Printf("[*] Removing current version\n")
	    					err = os.RemoveAll(filepath.Join(workingPath, "C2_Profiles", f.Name()))
	    					if err != nil {
	    						fmt.Printf("[-] Failed to remove current version: %v\n", err)
	    						fmt.Printf("[-] Continuing to the next c2 profile\n")
    							continue
	    					}else{
	    						fmt.Printf("[+] Successfully removed the current version\n")
	    					}
	    				}else{
	    					fmt.Printf("[!] Skipping C2 Profile, %s\n", f.Name())
	    					continue
	    				}
	    			}
	    			fmt.Printf("[*] Copying new version into place\n")
	    			err = copyDir(filepath.Join(installPath, "C2_Profiles", f.Name()), filepath.Join(workingPath, "C2_Profiles", f.Name()))
	    			if err != nil {
	    				fmt.Printf("[-] Failed to copy directory over\n")
	    				continue
	    			}
	    			// need to make sure the c2_service.sh file is executable
	    			if fileExists(filepath.Join(workingPath, "C2_Profiles", f.Name(), "mythic", "c2_service.sh")) {
	    				err = os.Chmod(filepath.Join(workingPath, "C2_Profiles", f.Name(), "mythic", "c2_service.sh"), 0777)
	    				if err != nil {
	    					fmt.Printf("[-] Failed to make c2_service.sh file executable\n")
	    					continue
	    				}
	    			} else {
	    				fmt.Printf("[-] failed to find c2_service file for %s\n", f.Name())
	    				continue
	    			}
	    			// now add payload type to yaml config
	    			fmt.Printf("[*] Adding c2, %s, into docker-compose\n", f.Name())
    				addRemoveDockerComposeEntries("add", "c2", []string{f.Name()},  make(map[string]interface{}), false, false)
	    		}
	    	}
	    	fmt.Printf("[+] Successfully installed c2\n")
	    }else{
	    	fmt.Printf("[*] Skipping over C2 Profile\n")
	    }
	    if !config.GetBool("exclude_documentation_payload") {
	    	// handle payload documentation copying here
	    	files, err := ioutil.ReadDir(filepath.Join(installPath, "documentation-payload"))
	    	if err != nil {
	    		fmt.Printf("[-] Failed to list contents of documentation_payload folder from clone\n")
	    		return err
	    	}
	    	for _, f := range files {
	    		if f.IsDir() {
	    			fmt.Printf("[*] Processing Documentation for %s\n", f.Name())
	    			if dirExists(filepath.Join(workingPath, "documentation-docker", "content", "Agents", f.Name())) {
	    				if overWrite || askConfirm("[*] " + f.Name() + " documentation already exists. Replace current version? "){
	    					fmt.Printf("[*] Removing current version\n")
	    					err = os.RemoveAll(filepath.Join(workingPath, "documentation-docker", "content", "Agents", f.Name()))
	    					if err != nil {
	    						fmt.Printf("[-] Failed to remove current version: %v\n", err)
	    						fmt.Printf("[-] Continuing to the next payload documentation\n")
	    						continue
	    					}else{
	    						fmt.Printf("[+] Successfully removed the current version\n")
	    					}
	    				}else{
	    					fmt.Printf("[!] Skipping documentation for , %s\n", f.Name())
	    					continue
	    				}
	    			}
	    			fmt.Printf("[*] Copying new documentation into place\n")
	    			err = copyDir(filepath.Join(installPath, "documentation-payload", f.Name()), filepath.Join(workingPath, "documentation-docker", "content", "Agents", f.Name()))
	    			if err != nil {
	    				fmt.Printf("[-] Failed to copy directory over\n")
	    				continue
	    			}
	    		}
	    	}
	    	fmt.Printf("[+] Successfully installed Payload documentation\n")
	    }else{
	    	fmt.Printf("[*] Skipping over Payload Documentation\n")
	    }
	    if !config.GetBool("exclude_documentation_c2") {
	    	// handle the c2 documentation copying here
	    	files, err := ioutil.ReadDir(filepath.Join(installPath, "documentation-c2"))
	    	if err != nil {
	    		fmt.Printf("[-] Failed to list contents of documentation_payload folder from clone")
	    		return err
	    	}
	    	for _, f := range files {
	    		if f.IsDir() {
	    			fmt.Printf("[*] Processing Documentation for %s\n", f.Name())
	    			if dirExists(filepath.Join(workingPath, "documentation-docker", "content", "C2 Profiles", f.Name())) {
	    				if overWrite || askConfirm("[*] " + f.Name() + " documentation already exists. Replace current version? "){
	    					fmt.Printf("[*] Removing current version\n")
	    					err = os.RemoveAll(filepath.Join(workingPath, "documentation-docker", "content", "C2 Profiles", f.Name()))
	    					if err != nil {
	    						fmt.Printf("[-] Failed to remove current version: %v\n", err)
	    						fmt.Printf("[-] Continuing to the next c2 documentation\n")
	    						continue
	    					}else{
	    						fmt.Printf("[+] Successfully removed the current version\n")
	    					}
	    				}else{
	    					fmt.Printf("[!] Skipping documentation for %s\n", f.Name())
	    					continue
	    				}
	    			}
	    			fmt.Printf("[*] Copying new documentation version into place\n")
	    			err = copyDir(filepath.Join(installPath, "documentation-c2", f.Name()), filepath.Join(workingPath, "documentation-docker", "content", "C2 Profiles", f.Name()))
	    			if err != nil {
	    				fmt.Printf("[-] Failed to copy directory over\n")
	    				continue
	    			}
	    		}
	    	}
	    	fmt.Printf("[+] Successfully installed c2 documentation\n")
	    }else{
	    	fmt.Printf("[*] Skipping over C2 Documentation\n")
	    }
	    if !config.GetBool("exclude_agent_icons") {
	    	// handle copying over the agent's svg icons
	    	files, err := ioutil.ReadDir(filepath.Join(installPath, "agent_icons"))
	    	if err != nil {
	    		fmt.Printf("[-] Failed to list contents of agent_icons folder from clone: %v\n", err)
	    		return err
	    	}
	    	for _, f := range files {
	    		if !f.IsDir() && f.Name() != ".gitkeep" && f.Name() != ".keep" {
	    			fmt.Printf("[*] Processing agent icon %s\n", f.Name())
	    			if fileExists(filepath.Join(workingPath, "mythic-docker", "app", "static", f.Name())) {
	    				if overWrite || askConfirm("[*] " + f.Name() + " agent icon already exists. Replace current version? "){
	    					fmt.Printf("[*] Removing current version\n")
	    					err = os.RemoveAll(filepath.Join(workingPath, "mythic-docker", "app", "static", f.Name()))
	    					if err != nil {
	    						fmt.Printf("[-] Failed to remove current version: %v\n", err)
	    						fmt.Printf("[-] Continuing to the next icon\n")
	    						continue
	    					}else{
    							fmt.Printf("[+] Successfully removed the current version\n")
	    					}
	    				}else{
	    					fmt.Printf("[!] Skipping agent icon for %s\n", f.Name())
	    					continue
	    				}
	    			}
	    			fmt.Printf("[*] Copying new icon version into place for old UI\n")
	    			err = copyFile(filepath.Join(installPath, "agent_icons", f.Name()), filepath.Join(workingPath, "mythic-docker", "app", "static", f.Name()))
	    			if err != nil {
	    				fmt.Printf("[-] Failed to copy icon over: %v\n", err)
	    				continue
	    			}
	    			if fileExists(filepath.Join(workingPath, "mythic-react-docker", "mythic", "public", f.Name())) {
	    				if overWrite || askConfirm("[*] " + f.Name() + " agent icon already exists for new UI. Replace current version? "){
	    					fmt.Printf("[*] Removing current version\n")
	    					err = os.RemoveAll(filepath.Join(workingPath, "mythic-react-docker", "mythic", "public", f.Name()))
	    					if err != nil {
	    						fmt.Printf("[-] Failed to remove current version: %v\n", err)
	    						fmt.Printf("[-] Continuing to the next agent icon\n")
	    						continue
	    					}else{
	    						fmt.Printf("[+] Successfully removed the current version\n")
	    					}
	    				}else{
	    					fmt.Printf("[!] Skipping new UI agent icon for %s\n", f.Name())
	    					continue
	    				}
	    			}
	    			fmt.Printf("[*] Copying new version into place for new UI\n")
	    			err = copyFile(filepath.Join(installPath, "agent_icons", f.Name()), filepath.Join(workingPath, "mythic-react-docker", "mythic", "public", f.Name()))
	    			if err != nil {
	    				fmt.Printf("[-] Failed to copy icon over: %v\n", err)
	    				continue
	    			}
	    		}
	    	}
	    	fmt.Printf("[+] Successfully installed agent icons\n")
	    }else{
	    	fmt.Printf("[*] Skipping over Agent Icons\n")
	    }
	    if isServiceRunning("mythic_documentation"){
	    	fmt.Printf("[*] Restarting mythic_documentation container to pull in changes\n")
	    	startStop("stop", "mythic", []string{"mythic_documentation"})
	    	startStop("start", "mythic", []string{"mythic_documentation"})
	    }
	}else{
		log.Fatal("[-] Failed to find config.json in cloned down repo\n")
	}
	return nil
}
func installAgent(url string, args []string) {
	// make our temp directory to clone into
	workingPath := getCwdFromExe()
	fmt.Printf("[*] Creating temporary directory\n")
	if dirExists(filepath.Join(workingPath, "tmp")) {
		err := os.RemoveAll(filepath.Join(workingPath, "tmp"))
		if err != nil {
			log.Fatalf("[-] tmp directory couldn't be deleted for a fresh install: %v\n", err)
		}
	}
	err := os.Mkdir(filepath.Join(workingPath, "tmp"), 0755)
	defer os.RemoveAll(filepath.Join(workingPath, "tmp"))
	if err != nil {
		log.Fatalf("[-] Failed to make temp directory for cloning: %v\n", err)
	}
	overWrite := false
	branch := ""
	if len(args) > 0 {
		if args[0] == "-f" {
			overWrite = true
		}else{
			branch = args[0]
		}
		if len(args) > 1 {
			if args[1] == "-f" {
				overWrite = true
			}
		}
	}
	if branch == "" {
		fmt.Printf("[*] Cloning %s\n", url)
		err = runGitClone([]string{"-c", "http.sslVerify=false", "clone", "--recurse-submodules", "--single-branch", url, filepath.Join(workingPath, "tmp")})
	}else{
		fmt.Printf("[*] Cloning branch \"%s\" from %s\n", branch, url)
		err = runGitClone([]string{"-c", "http.sslVerify=false", "clone", "--recurse-submodules", "--single-branch", "--branch", branch, url, filepath.Join(workingPath, "tmp")})
	}
	if err != nil {
		log.Fatalf("[-] Failed to clone down repository: %v\n", err)
	}
	if overWrite {
		err = installFolder(filepath.Join(workingPath, "tmp"), []string{"-f"})
	} else {
		err = installFolder(filepath.Join(workingPath, "tmp"), []string{})
	}
	if err != nil {
		log.Fatalf("[-] Failed to install: %v\n", err)
	}
}
func databaseReset() {
	fmt.Printf("[*] Stopping Mythic\n")
	startStop("stop", "mythic", []string{})
	workingPath := getCwdFromExe()
	fmt.Printf("[*] Removing database files\n")
	err := os.RemoveAll(filepath.Join(workingPath, "postgres-docker", "database"))
	if err != nil {
		fmt.Printf("[-] Failed to remove database files\n")
	}else{
		fmt.Printf("[+] Successfully reset datbase files\n")
	}	
}
func rabbitmqReset(explicitCall bool) {
	if explicitCall {
		fmt.Printf("[*] Stopping Mythic\n")
		startStop("stop", "mythic", []string{})
		fmt.Printf("[*] Removing rabbitmq files\n")
	}
	workingPath := getCwdFromExe()
	err := os.RemoveAll(filepath.Join(workingPath, "rabbitmq-docker", "storage"))
	if err != nil {
		log.Fatalf("[-] Failed to reset rabbitmq files: %v\n", err)
	}else{
		if explicitCall{
			fmt.Printf("[+] Successfully reset rabbitmq files\n")
		}
	}	
}
func checkPorts() error{
	// go through the different services in mythicEnv and check to make sure their ports aren't already used by trying to open them
	//MYTHIC_SERVER_HOST:MYTHIC_SERVER_PORT
	//POSTGRES_HOST:POSTGRES_PORT
	//HASURA_HOST:HASURA_PORT
	//RABBITMQ_HOST:RABBITMQ_PORT
	//DOCUMENTATION_HOST:DOCUMENTATION_PORT
	//REDIS_HOST:REDIS_PORT
	//NGINX_HOST:NGINX_PORT
	portChecks := map[string][]string{
		"MYTHIC_SERVER_HOST": []string{
			"MYTHIC_SERVER_PORT",
			"mythic_server",
		},
		"POSTGRES_HOST": []string{
			"POSTGRES_PORT",
			"mythic_postgres",
		},
		"HASURA_HOST": []string{
			"HASURA_PORT",
			"mythic_graphql",
		},
		"RABBITMQ_HOST": []string{
			"RABBITMQ_PORT",
			"mythic_rabbitmq",
		},
		"DOCUMENTATION_HOST": []string{
			"DOCUMENTATION_PORT",
			"mythic_documentation",
		},
		"NGINX_HOST": []string{
			"NGINX_PORT",
			"mythic_nginx",
		},
		"REDIS_HOST": []string{
			"REDIS_PORT",
			"mythic_redis",
		},
		"MYTHIC_REACT_HOST": []string{
			"MYTHIC_REACT_PORT",
			"mythic_react",
		},
	}
	var addServices []string
	var removeServices []string
	for key, val := range portChecks {
		if mythicEnv.GetString(key) == val[1] ||  mythicEnv.GetString(key) == "127.0.0.1" {
			addServices = append(addServices, val[1])
			p, err := net.Listen("tcp", ":" + strconv.Itoa(mythicEnv.GetInt(val[0])))
			if err != nil {
				fmt.Printf("[-] Port %d, from variable %s, appears to already be in use: %v\n", mythicEnv.GetInt(val[0]), key, err)
				return err
			}
			err = p.Close()
			if err != nil {
				fmt.Printf("[-] Failed to close connection: %v\n", err)
				return err
			}
		} else {
			removeServices = append(removeServices, val[1])
		}
	}
	addRemoveMythicServiceDockerEntries("add", addServices)
	addRemoveMythicServiceDockerEntries("remove", removeServices)
	return nil
}
func printMythicConnectionInfo(){
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, '\t', 0)
	fmt.Fprintln(w, "CONTAINER NAME\tMYTHIC SERVICE\tWEB ADDRESS\tBOUND LOCALLY")
	if mythicEnv.GetString("NGINX_HOST") == "mythic_nginx" {
		if mythicEnv.GetBool("NGINX_USE_SSL"){
			fmt.Fprintln(w, "mythic_nginx\tNginx (Mythic Web UI)\thttps://127.0.0.1:" + strconv.Itoa(mythicEnv.GetInt("NGINX_PORT")) + "\t", mythicEnv.GetBool("nginx_bind_localhost_only"))
		}else{
			fmt.Fprintln(w, "mythic_nginx\tNginx (Mythic Web UI)\thttp://127.0.0.1:" + strconv.Itoa(mythicEnv.GetInt("NGINX_PORT")) + "\t", mythicEnv.GetBool("nginx_bind_localhost_only"))
		}
	}else{
		if mythicEnv.GetBool("NGINX_USE_SSL"){
			fmt.Fprintln(w, "mythic_nginx\tNginx (Mythic Web UI)\thttps://" + mythicEnv.GetString("NGINX_HOST") + ":" + strconv.Itoa(mythicEnv.GetInt("NGINX_PORT")) + "\t", mythicEnv.GetBool("nginx_bind_localhost_only"))
		}else{
			fmt.Fprintln(w, "mythic_nginx\tNginx (Mythic Web UI)\thttp://" + mythicEnv.GetString("NGINX_HOST") + ":" + strconv.Itoa(mythicEnv.GetInt("NGINX_PORT")) + "\t", mythicEnv.GetBool("nginx_bind_localhost_only"))
		}
	}
	if mythicEnv.GetString("MYTHIC_SERVER_HOST") == "mythic_server" {
		fmt.Fprintln(w, "mythic_server\tMythic Backend Server\thttp://127.0.0.1:" + strconv.Itoa(mythicEnv.GetInt("MYTHIC_SERVER_PORT")) + "\t", mythicEnv.GetBool("mythic_server_bind_localhost_only"))
	}else{
		fmt.Fprintln(w, "mythic_server\tMythic Backend Server\thttp://" + mythicEnv.GetString("MYTHIC_SERVER_HOST") + ":" + strconv.Itoa(mythicEnv.GetInt("MYTHIC_SERVER_PORT")) + "\t", mythicEnv.GetBool("mythic_server_bind_localhost_only"))
	}
	if mythicEnv.GetString("HASURA_HOST") == "mythic_graphql" {
		fmt.Fprintln(w, "mythic_graphql\tHasura GraphQL Console\thttp://127.0.0.1:" + strconv.Itoa(mythicEnv.GetInt("HASURA_PORT")) + "\t", mythicEnv.GetBool("hasura_bind_localhost_only"))
	}else{
		fmt.Fprintln(w, "mythic_graphql\tHasura GraphQL Console\thttp://" + mythicEnv.GetString("HASURA_HOST") + ":" + strconv.Itoa(mythicEnv.GetInt("HASURA_PORT")) + "\t", mythicEnv.GetBool("hasura_bind_localhost_only"))
	}
	if mythicEnv.GetString("DOCUMENTATION_HOST") == "mythic_documentation" {
		fmt.Fprintln(w, "mythic_documentation\tInternal Documentation\thttp://127.0.0.1:" + strconv.Itoa(mythicEnv.GetInt("DOCUMENTATION_PORT"))  + "\t", mythicEnv.GetBool("documentation_bind_localhost_only"), "\n")
	}else{
		fmt.Fprintln(w, "mythic_documentation\tInternal Documentation\thttp://" + mythicEnv.GetString("DOCUMENTATION_HOST") + ":" + strconv.Itoa(mythicEnv.GetInt("DOCUMENTATION_PORT"))  + "\t", mythicEnv.GetBool("documentation_bind_localhost_only"), "\n")
	}
	
	fmt.Fprintln(w, "CONTAINER NAME\tADDITIONAL SERVICES\tIP\tPORT\tBOUND LOCALLY")
	if mythicEnv.GetString("POSTGRES_HOST") == "mythic_postgres" {
		fmt.Fprintln(w, "mythic_postgres\tPostgres Database\t127.0.0.1\t" + strconv.Itoa(mythicEnv.GetInt("POSTGRES_PORT")) + "\t", mythicEnv.GetBool("postgres_bind_localhost_only"))
	}else{
		fmt.Fprintln(w, "mythic_postgres\tPostgres Database\t" + mythicEnv.GetString("POSTGRES_HOST") + "\t" + strconv.Itoa(mythicEnv.GetInt("POSTGRES_PORT")) + "\t", mythicEnv.GetBool("postgres_bind_localhost_only"))
	}
	if mythicEnv.GetString("REDIS_HOST") == "mythic_redis" {
		fmt.Fprintln(w, "mythic_redis\tRedis Database\t127.0.0.1\t" + strconv.Itoa(mythicEnv.GetInt("REDIS_PORT")) + "\t", mythicEnv.GetBool("redis_bind_localhost_only"))
	}else{
		fmt.Fprintln(w, "mythic_redis\tRedis Database\t" + mythicEnv.GetString("REDIS_HOST") + "\t" + strconv.Itoa(mythicEnv.GetInt("REDIS_PORT")) + "\t", mythicEnv.GetBool("redis_bind_localhost_only"))
	}
	if mythicEnv.GetString("MYTHIC_REACT_HOST") == "mythic_react" {
		fmt.Fprintln(w, "mythic_react\tReact Server\t127.0.0.1\t" + strconv.Itoa(mythicEnv.GetInt("MYTHIC_REACT_PORT")) + "\t", mythicEnv.GetBool("mythic_react_bind_localhost_only"))
	}else{
		fmt.Fprintln(w, "mythic_react\tReact Server\t" + mythicEnv.GetString("MYTHIC_REACT_HOST") + "\t" + strconv.Itoa(mythicEnv.GetInt("MYTHIC_REACT_PORT")) + "\t", mythicEnv.GetBool("mythic_react_bind_localhost_only"))
	}
	if mythicEnv.GetString("RABBITMQ_HOST") == "mythic_rabbitmq" {
		fmt.Fprintln(w, "mythic_rabbitmq\tRabbitMQ\t127.0.0.1\t" + strconv.Itoa(mythicEnv.GetInt("RABBITMQ_PORT"))  + "\t", mythicEnv.GetBool("rabbitmq_bind_localhost_only"), "\n")
	}else{
		fmt.Fprintln(w, "mythic_rabbitmq\tRabbitMQ\t" + mythicEnv.GetString("RABBITMQ_HOST") + "\t" + strconv.Itoa(mythicEnv.GetInt("RABBITMQ_PORT"))  + "\t", mythicEnv.GetBool("rabbitmq_bind_localhost_only"), "\n")
	}
	w.Flush()
}
func testMythicConnection(){
	web_address := "127.0.0.1"
	if mythicEnv.GetString("NGINX_HOST") == "mythic_nginx" {
		if mythicEnv.GetBool("NGINX_USE_SSL"){
			web_address = "https://127.0.0.1"
		}else{
			web_address = "http://127.0.0.1"
		}
	}else{
		if mythicEnv.GetBool("NGINX_USE_SSL"){
			web_address = "https://" + mythicEnv.GetString("NGINX_HOST")
		}else{
			web_address = "http://" + mythicEnv.GetString("NGINX_HOST")
		}
	}
	maxCount := 10
	sleepTime := int64(10)
	count := make([]int, maxCount)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	fmt.Printf("[*] Waiting for Mythic Server and Nginx to come online (Retry Count = %d)\n", maxCount)
	for i, _ := range(count){
		fmt.Printf("[*] Attempting to connect to Mythic UI at %s:%d, attempt %d/%d\n", web_address, mythicEnv.GetInt("NGINX_PORT"), i + 1, maxCount)
		resp, err := http.Get(web_address + ":" + strconv.Itoa(mythicEnv.GetInt("NGINX_PORT")))
		if err != nil {
			fmt.Printf("[-] Failed to make connection to host, retrying in %ds\n", sleepTime)
			fmt.Printf("%v\n", err)
		}else{
			defer resp.Body.Close()
			if resp.StatusCode == 200 || resp.StatusCode == 404{
				fmt.Printf("[+] Successfully connected to Mythic at " + web_address + ":" + strconv.Itoa(mythicEnv.GetInt("NGINX_PORT")) + "\n\n")
				return
			}else if resp.StatusCode == 502 || resp.StatusCode == 504{
				fmt.Printf("[-] Nginx is up, but waiting for Mythic Server, retrying connection in %ds\n", sleepTime)
			}else {
				fmt.Printf("[-] Connection failed with HTTP Status Code %d, retrying in %ds\n", resp.StatusCode, sleepTime)
			}
		}
		time.Sleep(10 * time.Second)
	}
	fmt.Printf("[-] Failed to make connection to Mythic Server\n")
	fmt.Printf("    This could be due to limited resources on the host (recommended at least 2CPU and 4GB RAM)\n")
	fmt.Printf("    If there is an issue with Mythic server, use 'mythic-cli logs mythic_server' to view potential errors\n")
	status()
	fmt.Printf("[*] Fetching logs from mythic_server now:\n")
	logs("mythic_server")
	os.Exit(1)
}
func testMythicRabbitmqConnection(){
	rabbitmqAddress := "127.0.0.1"
	rabbitmqPort := mythicEnv.GetString("RABBITMQ_PORT")
	if mythicEnv.GetString("RABBITMQ_HOST") != "mythic_rabbitmq" && mythicEnv.GetString("RABBITMQ_HOST") != "127.0.0.1" {
		rabbitmqAddress = mythicEnv.GetString("RABBITMQ_HOST")
	}
	if rabbitmqAddress == "127.0.0.1" && !isServiceRunning("mythic_rabbitmq"){
		log.Fatalf("[-] Service mythic_rabbitmq should be running on the host, but isn't. Containers will be unable to connect.\nStart it by starting Mythic ('sudo ./mythic-cli mythic start') or manually with 'sudo ./mythic-cli mythic start mythic_rabbitmq'\n")
	}
	maxCount := 10
	var err error
	count := make([]int, maxCount)
	sleepTime := int64(10)
	fmt.Printf("[*] Waiting for RabbitMQ to come online (Retry Count = %d)\n", maxCount)
	for i, _ := range(count){
		fmt.Printf("[*] Attempting to connect to RabbitMQ at %s:%s, attempt %d/%d\n", rabbitmqAddress, rabbitmqPort, i+1, maxCount)
		conn, err := amqp.Dial(fmt.Sprintf("amqp://%s:%s@%s:%s/mythic_vhost", mythicEnv.GetString("RABBITMQ_USER"), mythicEnv.GetString("RABBITMQ_PASSWORD"), rabbitmqAddress, rabbitmqPort))
		if err != nil {
			fmt.Printf("[-] Failed to connect to RabbitMQ, retrying in %ds\n", sleepTime);
			time.Sleep(10 * time.Second)
		}else{
			defer conn.Close()
			fmt.Printf("[+] Successfully connected to RabbitMQ at amqp://%s:***@%s:%s/mythic_vhost\n\n", mythicEnv.GetString("RABBITMQ_USER"), rabbitmqAddress, rabbitmqPort)
			return
		}
	}
	fmt.Printf("[-] Failed to make a connection to the RabbitMQ server: %v\n", err)
	if isServiceRunning("mythic_rabbitmq"){
		log.Fatalf("    The mythic_rabbitmq service is running, but mythic-cli is unable to connect\n")
	}else{
		if rabbitmqAddress == "127.0.0.1"{
			log.Fatalf("    The mythic_rabbitmq service isn't running, but should be running locally. Did you start it?\n")
		}else{
			log.Fatalf("    The mythic_rabbitmq service isn't running locally, check to make sure it's running with the proper credentials\n")
		}
		
	}
}
func uninstallService(services []string){
	workingPath := getCwdFromExe()
	for _, service := range services {
		if stringInSlice(strings.ToLower(service), mythicServices){
			fmt.Printf("[-] Trying to uninstall Mythic services not allowed\n")
			os.Exit(1)
		}
		found := false
		if dirExists(filepath.Join(workingPath, "Payload_Types", service)){
			fmt.Printf("[*] Stopping and removing container\n")
			if isServiceRunning(strings.ToLower(service)){
				startStop("stop", "payload", []string{strings.ToLower(service)})
			}
			fmt.Printf("[*] Removing %s from docker-compose\n", strings.ToLower(service))
			addRemoveDockerComposeEntries("remove", "payload", []string{strings.ToLower(service)}, make(map[string]interface{}), true, false)
			fmt.Printf("[*] Removing Payload Type folder from disk\n")
			found = true
			err := os.RemoveAll(filepath.Join(workingPath, "Payload_Types", service))
			if err != nil {
				fmt.Printf("[-] Failed to remove folder: %v\n", err)
				os.Exit(1)
			}else{
				fmt.Printf("[+] Successfully removed %s's folder\n", service)
			}
			if dirExists(filepath.Join(workingPath, "documentation-docker", "content", "Agents", service)) {
				fmt.Printf("[*] Removing Payload Type's Documentation from disk\n")
				err = os.RemoveAll(filepath.Join(workingPath, "documentation-docker", "content", "Agents", service))
				if err != nil {
					fmt.Printf("[-] Failed to remove Payload Type's Documentation: %v\n", err)
					os.Exit(1)
				}else{
					fmt.Printf("[+] Successfully removed Payload Type's Documentation\n")
				}
			}
			if fileExists(filepath.Join(workingPath, "mythic-docker", "app", "static", service + ".svg")) {
				found = true
				err := os.RemoveAll(filepath.Join(workingPath, "mythic-docker", "app", "static", service + ".svg"))
				if err != nil {
					fmt.Printf("[-] Failed to agent icon: %v\n", err)
					os.Exit(1)
				}else{
					fmt.Printf("[+] Successfully removed %s's old UI icon\n", service)
				}
			}
			if fileExists(filepath.Join(workingPath, "mythic-react-docker", "mythic", "public", service + ".svg")) {
				found = true
				err := os.RemoveAll(filepath.Join(workingPath, "mythic-react-docker", "mythic", "public", service + ".svg"))
				if err != nil {
					fmt.Printf("[-] Failed to agent icon: %v\n", err)
					os.Exit(1)
				}else{
					fmt.Printf("[+] Successfully removed %s's new UI icon\n", service)
				}
			}
		}
		if dirExists(filepath.Join(workingPath, "C2_Profiles", service)){
			fmt.Printf("[*] Stopping and removing container\n")
			if isServiceRunning(strings.ToLower(service)){
				startStop("stop", "c2", []string{strings.ToLower(service)})
			}
			fmt.Printf("[*] Removing %s from docker-compose\n", strings.ToLower(service))
			addRemoveDockerComposeEntries("remove", "c2", []string{strings.ToLower(service)}, make(map[string]interface{}), true, false)
			fmt.Printf("[*] Removing C2 Profile from disk\n")
			found = true
			err := os.RemoveAll(filepath.Join(workingPath, "C2_Profiles", service))
			if err != nil {
				fmt.Printf("[-] Failed to remove folder: %v\n", err)
				os.Exit(1)
			}else{
				fmt.Printf("[+] Successfully removed %s's folder\n", service)
			}
			if dirExists(filepath.Join(workingPath, "documentation-docker", "content", "C2 Profiles", service)) {
				fmt.Printf("[*] Removing C2 Profile's Documentation\n")
				err = os.RemoveAll(filepath.Join(workingPath, "documentation-docker", "content", "C2 Profiles", service))
				if err != nil {
					fmt.Printf("[-] Failed to remove C2 Profile's Documentation: %v\n", err)
					os.Exit(1)
				}else{
					fmt.Printf("[+] Successfully removed C2 Profile's Documentation\n")
				}
			}
		}
		if found {
			fmt.Printf("[+] Successfully Uninstalled\n")
			if isServiceRunning("mythic_documentation"){
				fmt.Printf("[*] Restarting mythic_documentation container to pull in changes\n")
				startStop("stop", "mythic", []string{"mythic_documentation"})
				startStop("start", "mythic", []string{"mythic_documentation"})
			}
			return
		}else{
			fmt.Printf("[-] Failed to find any Payload Type or C2 Profile folder by that name\n")
			os.Exit(1)
		}
	}
}
func listGroupEntries(group string) {
	// list out which group entities exist in the docker-compose file
	dockerComposeEntries, err := getAllGroupNames(group)
	if err != nil {
		log.Fatalf("Failed to get group names from docker-compose: %v\n", err)
	}
	fmt.Printf("Docker-compose entries:\n")
	for _, entry := range dockerComposeEntries {
		fmt.Printf("[+] %s\n", entry)
	}
	var exclusion_list []string
	if group == "c2" {
		exclusion_list = strings.Split(mythicEnv.GetString("EXCLUDED_C2_PROFILES"), ",")
	} else if group == "payload" {
		exclusion_list = strings.Split(mythicEnv.GetString("EXCLUDED_PAYLOAD_TYPES"), ",")
	}
	if len(exclusion_list) > 0 && exclusion_list[0] != "" {
		fmt.Printf("Excluded entries from .env and environment variables:\n")
		for _, entry := range exclusion_list {
			fmt.Printf("[-] %s\n", entry)
		}
		
	}
	// list out which group entities exist on disk, which could be different than what's in the docker-compose file
	var targetFolder string
	var groupName string
	if group == "c2" {
		targetFolder = "C2_Profiles"
		groupName = "C2 Profiles"
	} else {
		targetFolder = "Payload_Types"
		groupName = "Payload Types"
	}
	files, err := ioutil.ReadDir(filepath.Join(getCwdFromExe(), targetFolder))
	if err != nil {
		fmt.Printf("[-] Failed to list contents of %s folder\n", targetFolder)
		return
	}
	fmt.Printf("\n%s on disk:\n", groupName)
	for _, f := range files {
		if f.IsDir() {
			fmt.Printf("[+] %s\n", f.Name())
		}
	}
	// list out which group entities are running
}
// code to generate self-signed certs pulled from github.com/kabukky/httpscerts
// and from http://golang.org/src/crypto/tls/generate_cert.go.
// only modifications were to use a specific elliptic curve cipher
func checkCerts(certPath string, keyPath string) error {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return err
	} else if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return err
	}
	return nil
}
func generateCerts() error {
	if !dirExists(filepath.Join(getCwdFromExe(), "nginx-docker", "ssl")) {
		err := os.MkdirAll(filepath.Join(getCwdFromExe(), "nginx-docker", "ssl"), os.ModePerm)
		if err != nil {
			fmt.Printf("[-] Failed to make ssl folder in nginx-docker folder\n")
			return err
		}
		fmt.Printf("[+] Successfully made ssl folder in nginx-docker folder\n")
	}
	certPath := filepath.Join(getCwdFromExe(), "nginx-docker", "ssl", "mythic-cert.crt")
	keyPath := filepath.Join(getCwdFromExe(), "nginx-docker", "ssl", "mythic-ssl.key")
	if checkCerts(certPath, keyPath) == nil {
		return nil
	}
	fmt.Printf("[*] Failed to find SSL certs for Nginx container, generating now...\n")
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("[-] failed to generate private key: %s\n", err)
		return err
	}
	notBefore := time.Now()
	oneYear := 365 * 24 * time.Hour
	notAfter := notBefore.Add(oneYear)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Printf("[-] failed to generate serial number: %s\n", err)
		return err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Mythic"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		fmt.Printf("[-] Failed to create certificate: %s\n", err)
		return err
	}
	certOut, err := os.Create(certPath)
	if err != nil {
		fmt.Printf("[-] failed to open "+certPath+" for writing: %s\n", err)
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open "+keyPath+" for writing:", err)
		return err
	}
	marshalKey, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		fmt.Printf("[-] Unable to marshal ECDSA private key: %v\n", err)
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type:"EC PRIVATE KEY", Bytes: marshalKey})
	keyOut.Close()
	fmt.Printf("[+] Successfully generated new SSL certs\n")
	return nil
}
func installMythicSyncFolder(installPath string){
	workingPath := getCwdFromExe()
	viper.SetConfigName("docker-compose")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(getCwdFromExe())
	if err := viper.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            log.Fatalf("[-] Error while reading in docker-compose file: %s\n", err)
        } else {
            log.Fatalf("[-] Error while parsing docker-compose file: %s\n", err)
        }
    }
    service := "mythic_sync"
    if isServiceRunning(service){
		startStop("stop", "mythic", []string{service})
	}
	if dirExists(filepath.Join(workingPath, service)) {
		err := os.RemoveAll(filepath.Join(workingPath, service))
		if err != nil {
			log.Fatalf("[-] %s directory couldn't be deleted for a fresh install: %v\n", filepath.Join(workingPath, service), err)
		}
	}
	err := copyDir(installPath, filepath.Join(workingPath, service))
	if err != nil {
		log.Fatalf("[-] Failed to create %s directory to install mythic_sync: %v\n", service, err)
	}
	var pStruct map[string]interface{}
	if viper.IsSet("services." + strings.ToLower(service)) {
		pStruct = viper.GetStringMap("services." + strings.ToLower(service))
		delete(pStruct, "network_mode")
	}else{
		pStruct = map[string]interface{}{
			"logging": map[string]interface{}{
				"driver": "json-file",
				"options": map[string]string{
					"max-file": "1",
					"max-size": "10m",
				},
			},
			"restart": "always",
			"labels": map[string]string{
				"name": service,
			},
			"container_name": service,
			"image": service,
		}
	}
	pStruct["logging"] = map[string]interface{}{
		"driver": "json-file",
		"options": map[string]string{
			"max-file": "1",
			"max-size": "10m",
		},
	}
	pStruct["restart"] = "always"
	pStruct["labels"] = map[string]string{
		"name": service,
	}
	pStruct["container_name"] = service
	pStruct["image"] = service
	pStruct["build"] = "./mythic_sync"
	pStruct["networks"] = []string{
		"default_network",
	}
	pStruct["environment"] = []string{
		"MYTHIC_IP=${NGINX_HOST}",
		"MYTHIC_PORT=${NGINX_PORT}",
		"MYTHIC_USERNAME=${MYTHIC_ADMIN_USER}",
		"MYTHIC_PASSWORD=${MYTHIC_ADMIN_PASSWORD}",
		"MYTHIC_API_KEY=${MYTHIC_API_KEY}",
		"REDIS_HOSTNAME=${REDIS_HOST}",
		"REDIS_PORT=${REDIS_PORT}",
		"GHOSTWRITER_API_KEY=${GHOSTWRITER_API_KEY}",
		"GHOSTWRITER_URL=${GHOSTWRITER_URL}",
		"GHOSTWRITER_OPLOG_ID=${GHOSTWRITER_OPLOG_ID}",
	}
	if !mythicEnv.IsSet("GHOSTWRITER_API_KEY"){
		key := askVariable("Please enter your GhostWriter API Key")
		mythicEnv.Set("GHOSTWRITER_API_KEY", key)
	}
	if !mythicEnv.IsSet("GHOSTWRITER_URL") {
		url := askVariable("Please enter your GhostWriter URL")
		mythicEnv.Set("GHOSTWRITER_URL", url)
	}
	if !mythicEnv.IsSet("GHOSTWRITER_OPLOG_ID") {
		gwID := askVariable("Please enter your GhostWriter OpLog ID")
		mythicEnv.Set("GHOSTWRITER_OPLOG_ID", gwID)
	}
	if !mythicEnv.IsSet("MYTHIC_API_KEY") {
		mythicID := askVariable("Please enter your Mythic API Key (optional)")
		mythicEnv.Set("MYTHIC_API_KEY", mythicID)
	}
	writeMythicEnvironmentVariables()
	if !viper.IsSet("services." + strings.ToLower(service)) {
		viper.Set("services." + strings.ToLower(service), pStruct)
		fmt.Printf("[+] Added %s to docker-compose\n", strings.ToLower(service))
	}else{
		viper.Set("services." + strings.ToLower(service), pStruct)
		fmt.Printf("[+] Updated %s in docker-compose\n", service)
	}
	network_info := map[string]interface{}{
		"default_network": map[string]interface{}{
			"driver": "bridge",
			"driver_opts": map[string]string{
				"com.docker.network.bridge.name": "mythic_if",
			},
			"ipam": map[string]interface{}{
				"config": []map[string]interface{}{
					map[string]interface{}{
						"subnet": "172.100.0.0/16",
					},
					
				},
				"driver": "default",
			},
			"labels": []string{
				"mythic_network",
				"default_network",
			},
		},
    }
    viper.Set("networks", network_info)
	err = viper.WriteConfig()
	if err != nil {
		log.Fatalf("[-] Failed to write out updated docker-compose file: %v\n", err)
	}
	fmt.Printf("[+] Successfully installed mythic_sync!\n")
	if isServiceRunning("mythic_server"){
		startStop("start", "mythic", []string{strings.ToLower(service)})
	}
}
func installMythicSync(args []string){
	if len(args) == 0 {
		log.Fatalf("[-] Missing install source - should be \"folder\" or \"github\"\n")
	}
	url := ""
	if args[0] == "github" {
		// make our temp directory to clone into
		workingPath := getCwdFromExe()
		fmt.Printf("[*] Creating temporary directory\n")
		if dirExists(filepath.Join(workingPath, "tmp")) {
			err := os.RemoveAll(filepath.Join(workingPath, "tmp"))
			if err != nil {
				log.Fatalf("[-] %s directory couldn't be deleted for a fresh install: %v\n", filepath.Join(workingPath, "tmp"), err)
			}
		}
		err := os.Mkdir(filepath.Join(workingPath, "tmp"), 0755)
		defer os.RemoveAll(filepath.Join(workingPath, "tmp"))
		if err != nil {
			log.Fatalf("[-] Failed to make temp directory for cloning: %v\n", err)
		}
		url = "https://github.com/GhostManager/mythic_sync"
		branch := ""
		if len(args[1:]) > 0 {
			for _, arg := range args[1:] {
				if strings.Contains(arg, "http") {
					url = arg
				} else {
					branch = arg
				}
			}
		}
		if branch == "" {
			fmt.Printf("[*] Cloning %s\n", url)
			err = runGitClone([]string{"-c", "http.sslVerify=false", "clone", "--recurse-submodules", "--single-branch", url, filepath.Join(workingPath, "tmp")})
		}else{
			fmt.Printf("[*] Cloning branch \"%s\" from %s\n", branch, url)
			err = runGitClone([]string{"-c", "http.sslVerify=false", "clone", "--recurse-submodules", "--single-branch", "--branch", branch, url, filepath.Join(workingPath, "tmp")})
		}
		if err != nil {
			log.Fatalf("[-] Failed to clone down repository: %v\n", err)
		}
		installMythicSyncFolder(filepath.Join(workingPath, "tmp"))

	}else if args[0] == "folder" {
		if len(args) != 2{
			log.Fatalf("[-] Wrong number of arguments: should be \"./mythic-cli mythic_sync install folder {path}")
		} else {
			url = args[1]
		}
		installMythicSyncFolder(url)
	} else {
		log.Fatalf("[-] Unknown install source - should be \"folder\" or \"github\"")
	}
}
func uninstallMythicSync(){
	workingPath := getCwdFromExe()
	viper.SetConfigName("docker-compose")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(getCwdFromExe())
	if err := viper.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            log.Fatalf("[-] Error while reading in docker-compose file: %s\n", err)
        } else {
            log.Fatalf("[-] Error while parsing docker-compose file: %s\n", err)
        }
    }
    service := "mythic_sync"
    if isServiceRunning(service){
		startStop("stop", "mythic", []string{service})
	}
	if viper.IsSet("services." + service) {
		delete(viper.Get("services").(map[string]interface{}), strings.ToLower(service))
		fmt.Printf("[+] Successfully removed %s from docker-compose\n", service)
	}else{
		fmt.Printf("[+] %s was not installed in docker-compose\n", service)
	}
	if dirExists(filepath.Join(workingPath, service)) {
		err := os.RemoveAll(filepath.Join(workingPath, service))
		if err != nil {
			log.Fatalf("[-] %s directory couldn't be deleted: %v\n", service, err)
		}else{
			fmt.Printf("[+] Successfully removed %s from disk\n", service)
		}
	}else{
		fmt.Printf("[+] %s was not installed on disk\n", service)
	}
	network_info := map[string]interface{}{
		"default_network": map[string]interface{}{
			"driver": "bridge",
			"driver_opts": map[string]string{
				"com.docker.network.bridge.name": "mythic_if",
			},
			"ipam": map[string]interface{}{
				"config": []map[string]interface{}{
					map[string]interface{}{
						"subnet": "172.100.0.0/16",
					},
					
				},
				"driver": "default",
			},
			"labels": []string{
				"mythic_network",
				"default_network",
			},
		},
    }
    viper.Set("networks", network_info)
	err := viper.WriteConfig()
	if err != nil {
		log.Fatalf("[-] Failed to remove mythic_sync: %v\n", err)
	}
	fmt.Printf("[+] Successfully uninstalled mythic_sync\n")
}
func main() {
    if len(os.Args) <= 1 {
        displayHelp()
        os.Exit(0)
    }
    parseMythicEnvironmentVariables()
    switch os.Args[1] {
	case "uninstall":
    	uninstallService(os.Args[2:])	
	case "status":
		status()
	case "logs":
		if len(os.Args) == 2 {
			log.Fatalf("[-] Missing name of container to view logs from")
		}
		logs(os.Args[2])
	case "config":
		env(os.Args[2:])
	case "mythic_sync":
		switch os.Args[2] {
		case "install":
			installMythicSync(os.Args[3:])
		case "uninstall":
			uninstallMythicSync()
		default:
			log.Fatalf("[-] Missing option to install or uninstall")
		}
	case "version":
		fmt.Printf("[*] mythic-cli version %s\n", mythicCliVersion)
    case "mythic":
    	fallthrough
    case "c2":
    	fallthrough	
    case "payload":
    	if len(os.Args) == 2 {
    		log.Fatalf("[-] Missing subcommand for %s", os.Args[1])
    	}
		switch os.Args[2]{
		case "start":
			err := generateCerts()
			if err != nil {
				os.Exit(1)
			}
			buildArguments = getBuildArguments()
			fallthrough
		case "stop":
			err := startStop(os.Args[2], os.Args[1], os.Args[3:])
			if err != nil {
				os.Exit(1)
			}
    	case "add":
    		fallthrough
    	case "remove":
    		buildArguments = getBuildArguments()
    		addRemoveDockerComposeEntries(os.Args[2], os.Args[1], os.Args[3:], make(map[string]interface{}), false, false)
    	case "list":
    		listGroupEntries(os.Args[1])
    	default:
    		log.Fatalf("[-] Unknown subcommand: %s", os.Args[2])
		}
    case "database":
    	if len(os.Args) == 2 {
    		log.Fatalf("[-] Missing subcommand for %s\n", os.Args[1])
    	}
    	databaseReset()
    case "rabbitmq":
    	if len(os.Args) == 2 {
    		log.Fatalf("[-] Missing subcommand for %s\n", os.Args[1])
    	}
    	rabbitmqReset(true)
    case "install":
    	if len(os.Args) <= 3 {
    		log.Fatalf("[-] Missing subcommand for %s\n", os.Args[1])
    	}
    	buildArguments = getBuildArguments()
    	if os.Args[2] == "github" {
    		installAgent(os.Args[3], os.Args[4:])
    	} else if os.Args[2] == "folder" {
    		installFolder(os.Args[3], os.Args[4:])
    	} else {
    		log.Fatalf("[-] unknown install location; should be 'github' or 'folder'\n")
    	} 
    case "start":
    	fallthrough
	case "restart":
    	err := generateCerts()
    	if err != nil {
    		os.Exit(1)
    	}
    	buildArguments = getBuildArguments()
    	err = startStop("start", "mythic", []string{})
    	if err != nil {
    		os.Exit(1)
    	}
	case "stop":
		err := startStop("stop", "mythic", []string{})
		if err != nil {
			os.Exit(1)
		}
	case "test":
		testMythicRabbitmqConnection()
		testMythicConnection()

    default:
        displayHelp()
        break
    }
}
