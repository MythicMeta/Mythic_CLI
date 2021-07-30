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
)

var mythicServices = []string{"mythic_postgres", "mythic_react", "mythic_server", "mythic_redis", "mythic_nginx", "mythic_rabbitmq", "mythic_graphql", "mythic_documentation"}
var mythicEnv = viper.New()
var mythicCliVersion = "0.0.4"

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
func displayHelp(){
    fmt.Println("mythic-cli usage ( v", mythicCliVersion, "):")
    fmt.Println("  help")
    fmt.Println("  mythic {start|stop} [service name...]")
    fmt.Println("  c2 {start|stop|add|remove|list} [c2profile ...]")
    fmt.Println("      The add/remove subcommands adjust the docker-compose file, not manipulate files on disk")
    fmt.Println("        to manipulate files on disk, use 'install' and 'uninstall' commands")
    fmt.Println("  payload {start|stop|add|remove|list} [payloadtype ...]")
    fmt.Println("      The add/remove subcommands adjust the docker-compose file, not manipulate files on disk")
    fmt.Println("        to manipulate files on disk, use 'install' and 'uninstall' commands")
    fmt.Println("  config")
    fmt.Println("      *no parameters will dump the entire config*")
    fmt.Println("      get [varname ...]")
    fmt.Println("      set <var name> <var value>")
    fmt.Println("  database reset")
    fmt.Println("  install ")
    fmt.Println("      github <url> [branch name] [-f]")
    fmt.Println("      folder <path to folder> [-f]")
    fmt.Println("      -f forces the removal of the currently installed version and overwrites with the new, otherwise will prompt you")
    fmt.Println("      * this command will manipulate files on disk and update docker-compose")
    fmt.Println("  uninstall {name}")
    fmt.Println("      (this command removes the payload or c2 profile from disk and updates docker-compose)")
    fmt.Println("  status")
    fmt.Println("  logs <container name>")
    fmt.Println("  version")
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
    // mythic server configuration
    mythicEnv.SetDefault("documentation_host", "127.0.0.1")
    mythicEnv.SetDefault("documentation_port", 8090)
    mythicEnv.SetDefault("mythic_debug", false)
    mythicEnv.SetDefault("mythic_server_port", 17443)
    mythicEnv.SetDefault("mythic_server_host", "127.0.0.1")
    // postgres configuration
    mythicEnv.SetDefault("postgres_host", "127.0.0.1")
    mythicEnv.SetDefault("postgres_port", 5432)
    mythicEnv.SetDefault("postgres_db", "mythic_db")
    mythicEnv.SetDefault("postgres_user", "mythic_user")
    mythicEnv.SetDefault("postgres_password", generateRandomPassword(30))
    // rabbitmq configuration
    mythicEnv.SetDefault("rabbitmq_host", "127.0.0.1")
    mythicEnv.SetDefault("rabbitmq_port", 5672)
    mythicEnv.SetDefault("rabbitmq_user", "mythic_user")
    mythicEnv.SetDefault("rabbitmq_password", generateRandomPassword(30))
    mythicEnv.SetDefault("rabbitmq_vhost", "mythic_vhost")
    // jwt configuration
    mythicEnv.SetDefault("jwt_secret", generateRandomPassword(30))
    // hasura configuration
    mythicEnv.SetDefault("hasura_host", "127.0.0.1")
    mythicEnv.SetDefault("hasura_port", 8080)
    mythicEnv.SetDefault("hasura_secret", generateRandomPassword(30))
    // redis configuration
    mythicEnv.SetDefault("redis_port", 6379)
    // docker-compose configuration
    mythicEnv.SetDefault("COMPOSE_PROJECT_NAME", "mythic")
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
		err := mythicEnv.WriteConfig()
		if err != nil {
			fmt.Printf("[-] Failed to write config: %v\n", err)
		}else{
			fmt.Printf("[+] Successfully updated configuration in .env\n")
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
			info := fmt.Sprintf("%s\t%s\t%s\t", container.Labels["name"], container.State, container.Status)
			if len(container.Ports) > 0 {
				for _, port := range container.Ports {
					if port.PublicPort > 0 {
						info = info + fmt.Sprintf("%d/%s -> %s:%d; ", port.PrivatePort, port.Type, port.IP, port.PublicPort)
					}
				}
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
		fmt.Printf("\nC2 Profile Services:\n")
		fmt.Fprintln(w, "NAME\tSTATE\tSTATUS\tPORTS")
		for _, line := range c2_services {
			fmt.Fprintln(w, line)
		}
		w.Flush()
	} else{
		fmt.Println("There are no containers running")
	}
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
	viper.SetConfigName("docker-compose")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(getCwdFromExe())
	if err := viper.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            fmt.Printf("[-] Error while reading in docker-compose file: %s", err)
            return []string{}, err
        } else {
            fmt.Printf("[-] Error while parsing docker-compose file: %s", err)
            return []string{}, err
        }
    }
	servicesSub := viper.Sub("services")
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
		build := servicesSub.GetString(container + ".build")
		buildAbsPath, err := filepath.Abs(build)
		if err != nil {
			fmt.Printf("[-] failed to get the absolute path to the container's docker file")
			continue
		}
		if strings.HasPrefix(buildAbsPath, absPath) {
			// the service we're looking at has a build path that's a child of our folder, it should be a service
			containerList = append(containerList, container)
		}
	}
	return containerList, nil
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
			mythicEnv.WriteConfig()
			fmt.Printf("[+] Successfully updated configuration in .env\n")
			
			if len(containerNames) > 0 {
				runDockerCompose(append([]string{"up", "--build", "-d"}, containerNames...))
			} else {
				runDockerCompose([]string{"down", "--volumes", "--remove-orphans"})
				rabbitmqReset()
				err := checkPorts()
				if err != nil {
					return err
				}
				c2ContainerList, err := getAllGroupNames("c2")
				if err != nil {
					fmt.Printf("[-] Failed to get all c2 services: %v\n", err)
					return err
				}
				c2ContainerList = removeExclusionsFromSlice("c2", c2ContainerList)
				payloadContainerList, err := getAllGroupNames("payload")
				if err != nil {
					fmt.Printf("[-] Failed to get all payload services: %v\n", err)
					return err
				}
				payloadContainerList = removeExclusionsFromSlice("payload", payloadContainerList)
				finalList := append(mythicServices, c2ContainerList...)
				finalList = append(finalList, payloadContainerList...)
				runDockerCompose(append([]string{"up", "--build", "-d"}, finalList...))
				testMythicConnection()
			}
			
			status()
		}
		if action == "stop" {
			if len(containerNames) > 0 {
				runDockerCompose(append([]string{"rm", "-s", "-v", "-f"}, containerNames...))
			} else {
				runDockerCompose(append([]string{"down", "--volumes", "--remove-orphans"}, containerNames...))
			}
			status()
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
					fmt.Printf("[*]   clear the list with: c2 config set excluded_c2_profiles ''\n")
					return nil
				}
				runDockerCompose(append([]string{"up", "--build", "-d"}, listWithoutExclusions...))
			} else if action == "stop" && len(containerList) > 0 {
				runDockerCompose(append([]string{"rm", "-s", "-v", "-f"}, containerList...))
			}
		}else{
			runDockerCompose(append([]string{"rm", "-s", "-v", "-f"}, containerNames...))
			if action == "start" && len(containerNames) > 0 {
				runDockerCompose(append([]string{"up", "--build", "-d"}, containerNames...))
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
					fmt.Printf("[*]   clear the list with: payload config set excluded_c2_profiles ''\n")
					return nil
				}
				runDockerCompose(append([]string{"up", "--build", "-d"}, listWithoutExclusions...))
			} else if action == "stop" && len(containerList) > 0 {
				runDockerCompose(append([]string{"rm", "-s", "-v", "-f"}, containerList...))
			}
		}else{
			runDockerCompose(append([]string{"rm", "-s", "-v", "-f"}, containerNames...))
			if action == "start" && len(containerNames) > 0 {
				runDockerCompose(append([]string{"up", "--build", "-d"}, containerNames...))
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
			fmt.Printf("Failed to read user input")
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
func addRemoveDockerComposeEntries(action string, group string, names []string, additionalConfigs map[string]interface{}, isUninstall bool) error {
	// add c2/payload [name] as type [group] to the main yaml file
	viper.SetConfigName("docker-compose")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(getCwdFromExe())
	if err := viper.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            log.Fatalf("[-] Error while reading in docker-compose file: %s", err)
        } else {
            log.Fatalf("[-] Error while parsing docker-compose file: %s", err)
        }
    }
    for _, payload := range names {
    	if action == "add" {
    		var absPath string
    		var err error
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
	    	pStruct := map[string]interface{}{
	    		"build": absPath,
	    		"network_mode": "host",
	    		"labels": map[string]string{
	    			"name": payload,
	    		},
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
	    		"environment": []string{
	    			"MYTHIC_ADDRESS=http://${MYTHIC_SERVER_HOST}:${MYTHIC_SERVER_PORT}/api/v1.4/agent_message",
					"MYTHIC_WEBSOCKET=ws://${MYTHIC_SERVER_HOST}:${MYTHIC_SERVER_PORT}/ws/agent_message",
					"MYTHIC_USERNAME=${RABBITMQ_USER}",
					"MYTHIC_PASSWORD=${RABBITMQ_PASSWORD}",
					"MYTHIC_VIRTUAL_HOST=${RABBITMQ_VHOST}",
					"MYTHIC_HOST=${RABBITMQ_HOST}",
	    		},
	    	}
	    	for key, element := range additionalConfigs {
	    		pStruct[key] = element
	    	}
			viper.Set("services." + strings.ToLower(payload), pStruct)
			viper.WriteConfig()
			fmt.Println("[+] Successfully updated docker-compose.yml")
			if isServiceRunning("mythic_server"){
				startStop("start", group, []string{strings.ToLower(payload)})
			}
    	}else if action == "remove" {
			// remove all entries from yaml file that are in `names`
			for _, payload := range names {
				if !stringInSlice(payload, mythicServices) {
					if isServiceRunning(payload){
						startStop("stop", group, []string{strings.ToLower(payload)})
					}
					delete(viper.Get("services").(map[string]interface{}), strings.ToLower(payload))
					if !isUninstall {
						fmt.Printf("[+] Removed %s from docker-compose, but files are still on disk. \nTo remove from disk use 'mythic-cli uninstall %s'\n", strings.ToLower(payload), strings.ToLower(payload))
					}else{
						fmt.Printf("[+] Removed %s from docker-compose\n", strings.ToLower(payload))
					}
				}
			}
			viper.WriteConfig()
			fmt.Println("[+] Successfully updated docker-compose.yml")
		}
    }
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
	    			} else {
	    				fmt.Printf("[-] failed to find payload_service file for %s\n", f.Name())
	    				continue
	    			}
	    			//find ./Payload_Types/ -name "payload_service.sh" -exec chmod +x {} \;
	    			// now add payload type to yaml config
	    			fmt.Printf("[*] Adding payload into docker-compose\n")
	    			if config.IsSet("docker-compose"){
	    				addRemoveDockerComposeEntries("add", "payload", []string{f.Name()}, config.GetStringMap("docker-compose"), false)
	    			}else{
	    				addRemoveDockerComposeEntries("add", "payload", []string{f.Name()}, make(map[string]interface{}), false)
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
    				addRemoveDockerComposeEntries("add", "c2", []string{f.Name()},  make(map[string]interface{}), false)
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
			log.Fatalf("[-] tmp directory couldn't be deleted for a fresh install: %v", err)
		}
	}
	err := os.Mkdir(filepath.Join(workingPath, "tmp"), 0755)
	defer os.RemoveAll(filepath.Join(workingPath, "tmp"))
	if err != nil {
		log.Fatalf("[-] Failed to make temp directory for cloning: %v", err)
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
	fmt.Printf("[*] Cloning %s\n", url)
	if branch == "" {
		err = runGitClone([]string{"-c", "http.sslVerify=false", "clone", "--recurse-submodules", "--single-branch", url, filepath.Join(workingPath, "tmp")})
	}else{
		err = runGitClone([]string{"-c", "http.sslVerify=false", "clone", "--recurse-submodules", "--single-branch", "--branch", branch, url, filepath.Join(workingPath, "tmp")})
	}
	if err != nil {
		log.Fatalf("[-] Failed to clone down repository: %v", err)
	}
	if overWrite {
		err = installFolder(filepath.Join(workingPath, "tmp"), []string{"-f"})
	} else {
		err = installFolder(filepath.Join(workingPath, "tmp"), []string{})
	}
	if err != nil {
		log.Fatalf("[-] Failed to install: %v", err)
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
func rabbitmqReset() {
	fmt.Printf("[*] Stopping Mythic\n")
	startStop("stop", "mythic", []string{})
	workingPath := getCwdFromExe()
	fmt.Printf("[*] Removing rabbitmq files\n")
	err := os.RemoveAll(filepath.Join(workingPath, "rabbitmq-docker", "storage"))
	if err != nil {
		fmt.Printf("[-] Failed to reset rabbitmq files\n")
	}else{
		fmt.Printf("[+] Successfully reset rabbitmq files\n")
	}	
}
func checkPorts() error{
	// go through the different services in mythicEnv and check to make sure their ports aren't already used by trying to open them
	//MYTHIC_SERVER_HOST:MYTHIC_SERVER_PORT
	//POSTGRES_HOST:POSTGRES_PORT
	//HASURA_HOST:HASURA_PORT
	//RABBITMQ_HOST:RABBITMQ_PORT
	//DOCUMENTATION_HOST:DOCUMENTATION_PORT
	//0.0.0.0:REDIS_PORT
	//0.0.0.0:NGINX_PORT
	portChecks := map[string]string{
		"MYTHIC_SERVER_HOST": "MYTHIC_SERVER_PORT",
		"POSTGRES_HOST": "POSTGRES_PORT",
		"HASURA_HOST": "HASURA_PORT",
		"RABBITMQ_HOST": "RABBITMQ_PORT",
		"DOCUMENTATION_HOST": "DOCUMENTATION_PORT",
	}
	for key, val := range portChecks {
		if mythicEnv.GetString(key) == "127.0.0.1" {
			p, err := net.Listen("tcp", ":" + strconv.Itoa(mythicEnv.GetInt(val)))
			if err != nil {
				fmt.Printf("[-] Port %d appears to already be in use: %v\n", mythicEnv.GetInt(val), err)
				return err
			}
			err = p.Close()
			if err != nil {
				fmt.Printf("[-] Failed to close connection: %v\n", err)
				return err
			}
		}
	}
	p, err := net.Listen("tcp", ":" + strconv.Itoa(mythicEnv.GetInt("REDIS_PORT")))
	if err != nil {
		fmt.Printf("[-] Port %d appears to already be in use: %v\n", mythicEnv.GetInt("REDIS_PORT"), err)
		return err
	}
	err = p.Close()
	if err != nil {
		fmt.Printf("[-] Failed to close connection: %v\n", err)
		return err
	}
	p, err = net.Listen("tcp", ":" + strconv.Itoa(mythicEnv.GetInt("NGINX_PORT")))
	if err != nil {
		fmt.Printf("[-] Port %d appears to already be in use: %v\n", mythicEnv.GetInt("NGINX_PORT"), err)
		return err
	}
	err = p.Close()
	return nil
}
func testMythicConnection(){
	maxCount := 10
	sleepTime := int64(10)
	count := make([]int, maxCount)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, '\t', 0)
	fmt.Fprintln(w, "MYTHIC SERVICE\tWEB ADDRESS")
	fmt.Fprintln(w, "Nginx (Mythic Web UI)\thttps://" + mythicEnv.GetString("MYTHIC_SERVER_HOST") + ":" + strconv.Itoa(mythicEnv.GetInt("NGINX_PORT")))
	fmt.Fprintln(w, "Mythic Backend Server\thttp://" + mythicEnv.GetString("MYTHIC_SERVER_HOST") + ":" + strconv.Itoa(mythicEnv.GetInt("MYTHIC_SERVER_PORT")))
	fmt.Fprintln(w, "Hasura GraphQL Console\thttp://" + mythicEnv.GetString("HASURA_HOST") + ":" + strconv.Itoa(mythicEnv.GetInt("HASURA_PORT")))
	fmt.Fprintln(w, "Internal Documentation\thttp://" + mythicEnv.GetString("DOCUMENTATION_HOST") + ":" + strconv.Itoa(mythicEnv.GetInt("DOCUMENTATION_PORT")) + "\n")
	w.Flush()
	for i, _ := range(count){
		fmt.Printf("[*] Attempting to connect to Mythic UI, attempt %d/%d\n", i + 1, maxCount)
		resp, err := http.Get("https://" + mythicEnv.GetString("MYTHIC_SERVER_HOST") + ":" + strconv.Itoa(mythicEnv.GetInt("NGINX_PORT")))
		if err != nil {
			fmt.Printf("[-] Failed to make https connection: %v, retrying in %ds\n", err, sleepTime)
		}else{
			defer resp.Body.Close()
			if resp.StatusCode == 200{
				fmt.Printf("[+] Successfully connected to Mythic at https://" + mythicEnv.GetString("MYTHIC_SERVER_HOST") + ":" + strconv.Itoa(mythicEnv.GetInt("NGINX_PORT")) + "\n")
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
	fmt.Printf("[*] Fetching logs from mythic_server now:")
	logs("mythic_server")
	os.Exit(1)
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
			addRemoveDockerComposeEntries("remove", "payload", []string{strings.ToLower(service)}, make(map[string]interface{}), true)
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
			addRemoveDockerComposeEntries("remove", "c2", []string{strings.ToLower(service)}, make(map[string]interface{}), true)
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
		fmt.Printf("[+] Mythic certificates already exist\n")
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
func main() {
    if len(os.Args) <= 1 {
        displayHelp()
        os.Exit(0)
    }
    switch os.Args[1] {
    case "mythic":
    	fallthrough
    case "c2":
    	fallthrough	
    case "payload":
    	if len(os.Args) == 2 {
    		log.Fatalf("[-] Missing subcommand for %s", os.Args[1])
    	}
		parseMythicEnvironmentVariables()
		switch os.Args[2]{
		case "start":
			err := generateCerts()
			if err != nil {
				os.Exit(1)
			}
			fallthrough
		case "stop":
			err := startStop(os.Args[2], os.Args[1], os.Args[3:])
			if err != nil {
				os.Exit(1)
			}
    	case "add":
    		fallthrough
    	case "remove":
    		addRemoveDockerComposeEntries(os.Args[2], os.Args[1], os.Args[3:], make(map[string]interface{}), false)
    	case "list":
    		listGroupEntries(os.Args[1])
    	default:
    		log.Fatalf("[-] Unknown subcommand: %s", os.Args[2])
		}
    case "database":
    	if len(os.Args) == 2 {
    		log.Fatalf("[-] Missing subcommand for %s\n", os.Args[1])
    	}
    	parseMythicEnvironmentVariables()
    	databaseReset()
    case "rabbitmq":
    	if len(os.Args) == 2 {
    		log.Fatalf("[-] Missing subcommand for %s\n", os.Args[1])
    	}
    	parseMythicEnvironmentVariables()
    	rabbitmqReset()
    case "install":
    	if len(os.Args) <= 3 {
    		log.Fatalf("[-] Missing subcommand for %s\n", os.Args[1])
    	}
    	parseMythicEnvironmentVariables()
    	if os.Args[2] == "github" {
    		installAgent(os.Args[3], os.Args[4:])
    	} else if os.Args[2] == "folder" {
    		installFolder(os.Args[3], os.Args[4:])
    	} else {
    		log.Fatalf("[-] unknown install location; should be 'github' or 'folder'\n")
    	} 
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
		parseMythicEnvironmentVariables()
		env(os.Args[2:])
	case "version":
		fmt.Printf("[*] mythic-cli version %s\n", mythicCliVersion)
    default:
        displayHelp()
        break
    }
}
