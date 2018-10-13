package container

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http/httputil"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/pkg/promise"
	"github.com/docker/docker/pkg/signal"
	"github.com/docker/libnetwork/resolvconf/dns"
	"github.com/manifoldco/promptui"
	"github.com/mbndr/logo"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/net/context"
)

const shadow = "ab5068f2bfb45860bbb73031ccd91a5d"

var (
	whitelist = vulnerabilitiesWhitelist{}
	logger    *logo.Logger
)

type runOptions struct {
	detach     bool
	sigProxy   bool
	name       string
	detachKeys string
}

// GetIntranetIP get ip to Clair
func GetIntranetIP() string {
	addrs, err := net.InterfaceAddrs()

	var ip []string

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, address := range addrs {

		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				//fmt.Println("ip:", ipnet.IP.String())
				ip = append(ip, ipnet.IP.String())
			}
		}
	}
	return ip[0]
}

// updatedockerfile create update image
func updatedockerfile(imageName string, home string) {

	deldockerfile := os.Remove(home + "Dockerfile/dockerfile")
	if deldockerfile != nil {
		fmt.Println(deldockerfile)
	}

	/*createupdatedockerfile, error := os.Create(home + "Dockerfile/dockerfile")
	if error != nil {
		fmt.Println(error)
	}
	fmt.Println(createupdatedockerfile)
	createupdatedockerfile.Close()*/

	outputFile, outputError := os.OpenFile(home+"Dockerfile/dockerfile", os.O_RDWR|os.O_CREATE, 0755)
	if outputError != nil {
		fmt.Printf("An error occurred with file opening or creation\n")
		return
	}
	defer outputFile.Close()

	updateimagename := imageName

	outputWriter := bufio.NewWriter(outputFile)
	outputString := "FROM " + updateimagename + "\n" + "RUN apt-get update "

	outputWriter.WriteString(outputString)
	outputWriter.Flush()
	return
}

func buildupdateimage(imageName string, home string) {

	var buildupdate []byte
	var errbuild error
	var cmdbuild *exec.Cmd
	imageName = "-t=" + imageName + ":update"
	home = home + "Dockerfile/"
	//file = home + "dockerfile"

	//cmdbuild = exec.Command("/usr/bin/chmod", "777", imageName, file)
	cmdbuild = exec.Command("/usr/bin/docker", "build", imageName, home)
	//cmdbuild = exec.Command("/usr/bin/echo", "$HOME")

	/*if cddockerfile, errcd = cmdcd.Output(); errcd != nil {
		fmt.Println(errcd)
		os.Exit(1)
	}
	fmt.Println(string(cddockerfile))*/

	if buildupdate, errbuild = cmdbuild.Output(); errbuild != nil {
		fmt.Println(errbuild)
		fmt.Println("build")
		os.Exit(1)
	}
	fmt.Println(string(buildupdate))
	return
}

// NewRunCommand create a new `docker run` command
func NewRunCommand(dockerCli *command.DockerCli) *cobra.Command {
	var opts runOptions
	var copts *containerOptions

	cmd := &cobra.Command{
		Use:   "run [OPTIONS] IMAGE [COMMAND] [ARG...]",
		Short: "Run a command in a new container",
		Args:  cli.RequiresMinArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			/*veri := cmd.Flags()
			fmt.Println(veri.Arg(0))
			fmt.Println(veri.Arg(1))*/

			f1, err1 := os.OpenFile("/tmp/docker-shadow", os.O_RDWR|os.O_CREATE, 0755)
			if err1 != nil {
				fmt.Println("Openfile failed")
				os.Exit(1)
			} else {
				content, err := ioutil.ReadFile("/tmp/docker-shadow")
				if err != nil {
					fmt.Println("Read docker-shadow failed")
				}
				content_str := string(content)
				if content_str == "" {
					err := ioutil.WriteFile("/tmp/docker-shadow", []byte(shadow), 0775)
					if err != nil {
						fmt.Println("Please check your user privilege.")
						panic(err)
					}
				}
			}

			var testpwd string

			fmt.Println("Executing \"docker run\" command...")
			testpwd = GetPwd("Enter the password:\n")
			data := []byte(testpwd)
			has := md5.Sum(data)
			md5str1 := fmt.Sprintf("%x", has)

			content, err := ioutil.ReadFile("/tmp/docker-shadow")
			if err != nil {
				fmt.Println("Read docker-shadow failed")
			}
			content_str := string(content)

			if md5str1 == content_str {
				fmt.Println("Correct!")
			} else {
				fmt.Println("Wrong password! permission denied.")
				os.Exit(1)
			}

			if err := f1.Close(); err != nil {
				fmt.Println("docker-shadow closing failed")
			}

			copts.Image = args[0]
			if len(args) > 1 {
				copts.Args = args[1:]
			}
			return runRun(dockerCli, cmd.Flags(), &opts, copts)
		},
	}

	flags := cmd.Flags()
	flags.SetInterspersed(false)

	// These are flags not stored in Config/HostConfig
	flags.BoolVarP(&opts.detach, "detach", "d", false, "Run container in background and print container ID")
	flags.BoolVar(&opts.sigProxy, "sig-proxy", true, "Proxy received signals to the process")
	flags.StringVar(&opts.name, "name", "", "Assign a name to the container")
	flags.StringVar(&opts.detachKeys, "detach-keys", "", "Override the key sequence for detaching a container")

	// Add an explicit help that doesn't have a `-h` to prevent the conflict
	// with hostname
	flags.Bool("help", false, "Print usage")

	command.AddTrustVerificationFlags(flags)
	copts = addFlags(flags)
	return cmd
}

func warnOnOomKillDisable(hostConfig container.HostConfig, stderr io.Writer) {
	if hostConfig.OomKillDisable != nil && *hostConfig.OomKillDisable && hostConfig.Memory == 0 {
		fmt.Fprintln(stderr, "WARNING: Disabling the OOM killer on containers without setting a '-m/--memory' limit may be dangerous.")
	}
}

// check the DNS settings passed via --dns against localhost regexp to warn if
// they are trying to set a DNS to a localhost address
func warnOnLocalhostDNS(hostConfig container.HostConfig, stderr io.Writer) {
	for _, dnsIP := range hostConfig.DNS {
		if dns.IsLocalhost(dnsIP) {
			fmt.Fprintf(stderr, "WARNING: Localhost DNS setting (--dns=%s) may fail in containers.\n", dnsIP)
			return
		}
	}
}

// detectmain detect image vulnerability
func detectmain(image string, currentip string) {
	var (
		whitelistFile      = ""
		whitelistThreshold = "Unknown"
		clair              = "http://127.0.0.1:6060"
		ip                 = currentip
		logFile            = ""
		reportAll          = true
		reportFile         = ""
		imageName          = image
	)

	initializeLogger(logFile)
	if whitelistFile != "" {
		whitelist = parseWhitelistFile(whitelistFile)
	}
	validateThreshold(whitelistThreshold)

	logger.Info("Start clair-scanner")

	go listenForSignal(func(s os.Signal) {
		log.Fatalf("Application interrupted [%v]", s)
	})

	result := scan(scannerConfig{
		imageName,
		whitelist,
		clair,
		ip,
		reportFile,
		whitelistThreshold,
		reportAll,
	})

	// action after detect
	if len(result) > 0 {
		logger.Info(result)
		logger.Info("Do you want to update the vulnerable image?")
		prompt := promptui.Select{
			Label: "Select yes/no",
			Items: []string{"yes", "no"},
		}

		_, updatereply, err := prompt.Run()

		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		fmt.Printf("You choose %q\n", updatereply)

		if updatereply == "yes" {
			var home string
			logger.Info("Please Enter your $PATH ( ex : /home/user/ )")
			fmt.Scanln(&home)
			updatedockerfile(imageName, home)
			buildupdateimage(imageName, home)
		} else if updatereply == "no" {
			fmt.Println("NO")
			return
		}
		os.Exit(1)
	} else {
		fmt.Println("OK")
		return
	}
}

func initializeLogger(logFile string) {
	cliRec := logo.NewReceiver(os.Stderr, "")
	cliRec.Color = true

	if logFile != "" {
		file, err := logo.Open(logFile)
		if err != nil {
			fmt.Printf("Could not initialize logging file %v", err)
			os.Exit(1)
		}

		fileRec := logo.NewReceiver(file, "")
		logger = logo.NewLogger(cliRec, fileRec)
	} else {
		logger = logo.NewLogger(cliRec)
	}
}

func runRun(dockerCli *command.DockerCli, flags *pflag.FlagSet, opts *runOptions, copts *containerOptions) error {
	containerConfig, err := parse(flags, copts)
	// just in case the parse does not exit
	if err != nil {
		reportError(dockerCli.Err(), "run", err.Error(), true)
		return cli.StatusError{StatusCode: 125}
	}
	return runContainer(dockerCli, opts, copts, containerConfig)
}

func runContainer(dockerCli *command.DockerCli, opts *runOptions, copts *containerOptions, containerConfig *containerConfig) error {

	config := containerConfig.Config
	hostConfig := containerConfig.HostConfig
	stdout, stderr := dockerCli.Out(), dockerCli.Err()
	client := dockerCli.Client()

	/*// get the current ip
	currentip := GetIntranetIP()

	//  detect the image is clair
	imagename := config.Image
	imageclair := strings.Contains(imagename, "arminc/clair")
	if imageclair {
	} else {
		detectmain(config.Image, currentip)
	}*/

	// TODO: pass this as an argument
	cmdPath := "run"

	warnOnOomKillDisable(*hostConfig, stderr)
	warnOnLocalhostDNS(*hostConfig, stderr)

	config.ArgsEscaped = false

	if !opts.detach {
		if err := dockerCli.In().CheckTty(config.AttachStdin, config.Tty); err != nil {
			return err
		}
	} else {
		if copts.attach.Len() != 0 {
			return errors.New("Conflicting options: -a and -d")
		}

		config.AttachStdin = false
		config.AttachStdout = false
		config.AttachStderr = false
		config.StdinOnce = false
	}

	// Disable sigProxy when in TTY mode
	if config.Tty {
		opts.sigProxy = false
	}

	// Telling the Windows daemon the initial size of the tty during start makes
	// a far better user experience rather than relying on subsequent resizes
	// to cause things to catch up.
	if runtime.GOOS == "windows" {
		hostConfig.ConsoleSize[0], hostConfig.ConsoleSize[1] = dockerCli.Out().GetTtySize()
	}

	ctx, cancelFun := context.WithCancel(context.Background())

	createResponse, err := createContainer(ctx, dockerCli, containerConfig, opts.name)
	if err != nil {
		reportError(stderr, cmdPath, err.Error(), true)
		return runStartContainerErr(err)
	}
	if opts.sigProxy {
		sigc := ForwardAllSignals(ctx, dockerCli, createResponse.ID)
		defer signal.StopCatch(sigc)
	}
	var (
		waitDisplayID chan struct{}
		errCh         chan error
	)
	if !config.AttachStdout && !config.AttachStderr {
		// Make this asynchronous to allow the client to write to stdin before having to read the ID
		waitDisplayID = make(chan struct{})
		go func() {
			defer close(waitDisplayID)
			fmt.Fprintln(stdout, createResponse.ID)
		}()
	}
	attach := config.AttachStdin || config.AttachStdout || config.AttachStderr
	if attach {
		if opts.detachKeys != "" {
			dockerCli.ConfigFile().DetachKeys = opts.detachKeys
		}

		close, err := attachContainer(ctx, dockerCli, &errCh, config, createResponse.ID)
		defer close()
		if err != nil {
			return err
		}
	}

	statusChan := waitExitOrRemoved(ctx, dockerCli, createResponse.ID, copts.autoRemove)

	//start the container
	if err := client.ContainerStart(ctx, createResponse.ID, types.ContainerStartOptions{}); err != nil {
		// If we have holdHijackedConnection, we should notify
		// holdHijackedConnection we are going to exit and wait
		// to avoid the terminal are not restored.
		if attach {
			cancelFun()
			<-errCh
		}

		reportError(stderr, cmdPath, err.Error(), false)
		if copts.autoRemove {
			// wait container to be removed
			<-statusChan
		}
		return runStartContainerErr(err)
	}

	if (config.AttachStdin || config.AttachStdout || config.AttachStderr) && config.Tty && dockerCli.Out().IsTerminal() {
		if err := MonitorTtySize(ctx, dockerCli, createResponse.ID, false); err != nil {
			fmt.Fprintln(stderr, "Error monitoring TTY size:", err)
		}
	}

	if errCh != nil {
		if err := <-errCh; err != nil {
			logrus.Debugf("Error hijack: %s", err)
			return err
		}
	}

	// Detached mode: wait for the id to be displayed and return.
	if !config.AttachStdout && !config.AttachStderr {
		// Detached mode
		<-waitDisplayID
		return nil
	}

	status := <-statusChan
	if status != 0 {
		return cli.StatusError{StatusCode: status}
	}
	return nil
}

func attachContainer(
	ctx context.Context,
	dockerCli *command.DockerCli,
	errCh *chan error,
	config *container.Config,
	containerID string,
) (func(), error) {
	stdout, stderr := dockerCli.Out(), dockerCli.Err()
	var (
		out, cerr io.Writer
		in        io.ReadCloser
	)
	if config.AttachStdin {
		in = dockerCli.In()
	}
	if config.AttachStdout {
		out = stdout
	}
	if config.AttachStderr {
		if config.Tty {
			cerr = stdout
		} else {
			cerr = stderr
		}
	}

	options := types.ContainerAttachOptions{
		Stream:     true,
		Stdin:      config.AttachStdin,
		Stdout:     config.AttachStdout,
		Stderr:     config.AttachStderr,
		DetachKeys: dockerCli.ConfigFile().DetachKeys,
	}

	resp, errAttach := dockerCli.Client().ContainerAttach(ctx, containerID, options)
	if errAttach != nil && errAttach != httputil.ErrPersistEOF {
		// ContainerAttach returns an ErrPersistEOF (connection closed)
		// means server met an error and put it in Hijacked connection
		// keep the error and read detailed error message from hijacked connection later
		return nil, errAttach
	}

	*errCh = promise.Go(func() error {
		if errHijack := holdHijackedConnection(ctx, dockerCli, config.Tty, in, out, cerr, resp); errHijack != nil {
			return errHijack
		}
		return errAttach
	})
	return resp.Close, nil
}

// reportError is a utility method that prints a user-friendly message
// containing the error that occurred during parsing and a suggestion to get help
func reportError(stderr io.Writer, name string, str string, withHelp bool) {
	str = strings.TrimSuffix(str, ".") + "."
	if withHelp {
		str += "\nSee '" + os.Args[0] + " " + name + " --help'."
	}
	fmt.Fprintf(stderr, "%s: %s\n", os.Args[0], str)
}

// if container start fails with 'not found'/'no such' error, return 127
// if container start fails with 'permission denied' error, return 126
// return 125 for generic docker daemon failures
func runStartContainerErr(err error) error {
	trimmedErr := strings.TrimPrefix(err.Error(), "Error response from daemon: ")
	statusError := cli.StatusError{StatusCode: 125}
	if strings.Contains(trimmedErr, "executable file not found") ||
		strings.Contains(trimmedErr, "no such file or directory") ||
		strings.Contains(trimmedErr, "system cannot find the file specified") {
		statusError = cli.StatusError{StatusCode: 127}
	} else if strings.Contains(trimmedErr, syscall.EACCES.Error()) {
		statusError = cli.StatusError{StatusCode: 126}
	}

	return statusError
}
