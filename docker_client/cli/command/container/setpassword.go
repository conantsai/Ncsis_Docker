package container

import (
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/spf13/cobra"
)

// NewRunCommand create a new `docker run` command
func NewPassword(dockerCli *command.DockerCli) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "setpwd",
		Short: "setpassword",
		Args:  cli.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {

			var newPwd, oldPwd string

			f, err := os.OpenFile("/tmp/docker-shadow", os.O_RDWR|os.O_CREATE, 0755)
			if err != nil {
				fmt.Println("Openfile failed")
			} else {
				content, err := ioutil.ReadFile("/tmp/docker-shadow")
				if err != nil {
					fmt.Println("Read docker-shadow failed")
				}

				content_str := string(content)
				if content_str == "" {
					err := ioutil.WriteFile("/tmp/docker-shadow", []byte(shadow), 0775)
					if err != nil {
						panic(err)
					}
				}
			}
			content, err := ioutil.ReadFile("/tmp/docker-shadow")
			if err != nil {
				fmt.Println("Read docker-shadow failed")
			} else {
				content_str := string(content)
				//fmt.Println("Enter old password:\n")
				//fmt.Scanln(&oldPwd)
				oldPwd = GetPwd("Enter old password:\n")
				data := []byte(oldPwd)
				has := md5.Sum(data)
				oldMd5Str := fmt.Sprintf("%x", has)
				if oldMd5Str == content_str {
					//fmt.Println("Enter old password:\n")
					//fmt.Scanln(&newPwd)
					newPwd = GetPwd("Enter new password:\n")
					data := []byte(newPwd)
					has := md5.Sum(data)
					newMd5Str := fmt.Sprintf("%x", has)
					err := ioutil.WriteFile("/tmp/docker-shadow", []byte(newMd5Str), 0775)
					if err != nil {
						panic(err)
					}
				} else {
					fmt.Println("Wrong password, permission denied")
				}
			}
			if err := f.Close(); err != nil {
				fmt.Println("docker-shadow closing failed")
			}

		},
	}

	return cmd
}
