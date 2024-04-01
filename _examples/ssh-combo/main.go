package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"embed" //no lint
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"github.com/runletapp/go-console"
	gossh "golang.org/x/crypto/ssh"
)

const (
	sshHostKey                   = "ssh_host_rsa_key"               // OpenSSH for Windows
	administratorsAuthorizedKeys = "administrators_authorized_keys" // OpenSSH for Windows
	authorizedKeys               = "authorized_keys"                // stored from embed
)

var (
	//go:embed authorized_keys
	authorized_keys []byte

	//go:embed winpty/*
	winpty_deps embed.FS

	key     ssh.Signer
	allowed []ssh.PublicKey
)

func SessionRequestCallback(s ssh.Session, requestType string) bool {
	log.Println(s.RemoteAddr(), requestType)
	return true
}

func SftpHandler(s ssh.Session) {
	debugStream := ioutil.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(
		s,
		serverOptions...,
	)
	if err != nil {
		log.Printf("sftp server init error: %s\n", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		fmt.Println("sftp client exited session.")
	} else if err != nil {
		fmt.Println("sftp server completed with error:", err)
	}
}

// 添加到authorized_keys的函数
func appendToAuthorizedKeys(publicKeyPath string) error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	sshDir := filepath.Join(currentUser.HomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")

	// 读取公钥内容
	pubKeyBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}

	// 打开或创建authorized_keys文件，并追加公钥
	file, err := os.OpenFile(authorizedKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(pubKeyBytes); err != nil {
		return err
	}

	return nil
}

// generateKeyPair generates a new RSA private and public key pair.
func generateKeyPair(privateKeyPath string, publicKeyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Generate and write private key
	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(privateKeyPath, 0600); err != nil {
		return err
	}
	defer privateKeyFile.Close()

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return err
	}

	// Generate and write public key
	pub, err := gossh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(publicKeyPath, gossh.MarshalAuthorizedKey(pub), 0600)
}

func toAllowed(bs []byte, err error) (allowed []ssh.PublicKey) {
	if err != nil {
		return
	}
	for _, b := range bytes.Split(bs, []byte("\n")) {
		k, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err == nil {
			allowed = append(allowed, k)
		}
	}
	return
}

func setPrivateKeyPermissions(privateKeyPath string) error {
	computerName := os.Getenv("COMPUTERNAME")
	userName := os.Getenv("USERNAME")

	// 构建icacls命令参数，注意参数中包含空格的需要用引号括起来
	commands := []string{
		fmt.Sprintf(`icacls "%s" /grant "NT Service\\sshd:R" /inheritance:r`, privateKeyPath),
		fmt.Sprintf(`icacls "%s" /remove "%s\\%s"`, privateKeyPath, computerName, userName),
		fmt.Sprintf(`icacls "%s" /inheritance:r`, privateKeyPath),
		fmt.Sprintf(`icacls "%s" /grant "BUILTIN\\Administrators:F"`, privateKeyPath),
		fmt.Sprintf(`icacls "%s" /grant "NT AUTHORITY\\SYSTEM:F"`, privateKeyPath),
	}

	for _, cmdStr := range commands {
		// 分割命令字符串为命令名和参数
		cmd := exec.Command("cmd", "/C", cmdStr)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute command: %s, error: %w", cmdStr, err)
		}
	}

	return nil
}


func UserHomeDir() string {
    if runtime.GOOS == "windows" {
        home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
        if home == "" {
            home = os.Getenv("USERPROFILE")
        }
        return home
    }
    return os.Getenv("HOME")
}

func main() {
	var (
		ip   string
		port int
		genT bool
		username string
		password string
	)
	flag.StringVar(&ip, "ip", "0.0.0.0", "IP address to listen on")
	flag.IntVar(&port, "port", 2222, "Port to listen on")
	flag.StringVar(&username, "username", "", "Server login username")
	flag.StringVar(&password, "password", "", "Server login password")
	flag.BoolVar(&genT, "gt", false, "Generate new SSH key pair")
	flag.Parse()
	log.Println(UnloadEmbeddedDeps())
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
		return
	}
	pri := filepath.Join(cwd, sshHostKey)
	if genT {
		cwd, _ := os.Getwd()
		priPath := filepath.Join(cwd, sshHostKey)
		pubPath := priPath + ".pub"
		if err := generateKeyPair(priPath, pubPath); err != nil {
			log.Fatalf("Error generating key pair: %v", err)
		}
		fmt.Println("Generated new SSH key pair")
		if err := appendToAuthorizedKeys(pubPath); err != nil {
			log.Fatalf("Error appending public key to authorized_keys: %v", err)
		} else {
			log.Printf("Appended public key to authorized_keys: %s\n", pubPath)
		}
		fmt.Println("Public key appended to authorized_keys")
		// err = setPrivateKeyPermissions(pri)
		// if err!= nil {
		// 	log.Fatalf("Error setting private key permissions: %v", err)
		// } else {
		// 	log.Printf("Private key permissions set")
		// }
		return
	}
	// err = setPrivateKeyPermissions(pri)
	// if err!= nil {
    //     log.Fatalf("Error setting private key permissions: %v", err)
    // } else {
    //     log.Printf("Private key permissions set")
    // }
	pemBytes, err := ioutil.ReadFile(pri)
	if err != nil {
		log.Fatal("Could not read private key file: ", err)
		return
		// key, err = generateSigner(pri, pub)
	} else {
		key, err = gossh.ParsePrivateKey(pemBytes)
	}
	if err != nil {
		log.Fatal(err)
		return
	}
	programDataPath := os.Getenv("ProgramData")
	for _, akf := range []string{
		filepath.Join(programDataPath, administratorsAuthorizedKeys),
		// filepath.Join(os.ExpandEnv("ProgramData"), administratorsAuthorizedKeys),
		filepath.Join(UserHomeDir(), ".ssh", authorizedKeys),
		filepath.Join(cwd, authorizedKeys),
	} {
		log.Printf("Trying to read authorized keys from: %s\n", os.ExpandEnv(akf))
		kk := toAllowed(ioutil.ReadFile(akf))
		if len(kk) > 0 {
			log.Printf("Successfully loaded authorized keys from: %s\n", os.ExpandEnv(akf))
		}
		allowed = append(allowed, kk...)
	}

	if len(allowed) == 0 {
		log.Fatal("No authorized keys found")
	}
	// if len(allowed) == 0 {
	// 	//no files
	// 	allowed = toAllowed(authorized_keys, nil)
	// 	if len(allowed) > 0 {
	// 		ioutil.WriteFile(filepath.Join(cwd, authorizedKeys), authorized_keys, 0600)
	// 	}
	// }

	ForwardedTCPHandler := &ssh.ForwardedTCPHandler{}
	addr := fmt.Sprintf("%s:%d", ip, port)
	log.Printf("Starting ssh server on %s\n", addr)
	sshd := ssh.Server{
		// Addr: ":2222",
		Addr: addr,
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session":      ssh.DefaultSessionHandler,
			"direct-tcpip": ssh.DirectTCPIPHandler, // ssh -L
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        ForwardedTCPHandler.HandleSSHRequest,
			"cancel-tcpip-forward": ForwardedTCPHandler.HandleSSHRequest,
		},
		LocalPortForwardingCallback: ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool {
			log.Println("accepted forward", dhost, dport) // ssh -L x:dhost:dport
			return true
		}),
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool {
			log.Println("attempt to bind", host, port, "granted") // ssh -R port:x:x
			return true
		}),
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": SftpHandler,
		},
		SessionRequestCallback: SessionRequestCallback,
	}
	if username != "" && password != "" { 
		sshd.PasswordHandler = func(ctx ssh.Context, passwordT string) bool {
			// 替换为你的验证逻辑
			return ctx.User() == username && passwordT == password
		}
	}

	sshd.AddHostKey(key)
	if len(sshd.HostSigners) < 1 {
		log.Fatal("host key was not properly added")
		return
	} else {
		log.Println("host key added")
	}

	publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
		// 将客户端提供的公钥转换为可读的格式
		authorizedKey := gossh.MarshalAuthorizedKey(key)
		log.Printf("Trying to authenticate user %s with public key: %s\n", ctx.User(), string(authorizedKey))
	
		for _, k := range allowed {
			// fmt.Println("key",key,"k",k)
			if ssh.KeysEqual(key, k) {
				log.Println("Authentication succeeded.")
				return true
			}
		}
		log.Println("Authentication failed.")
		return false
	})
	sshd.SetOption(publicKeyOption)
	ssh.Handle(func(s ssh.Session) {
		io.WriteString(s, fmt.Sprintf("user: %s\n", s.User()))
		if s.PublicKey() != nil {
			authorizedKey := gossh.MarshalAuthorizedKey(s.PublicKey())
			io.WriteString(s, fmt.Sprintf("used public key:\n%s", authorizedKey))
		}
		cmdPTY(s)
	})

	log.Println("starting ssh server on", sshd.Addr)
	log.Fatal(sshd.ListenAndServe())
}

func generateSigner(pri, pub string) (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	Bytes := x509.MarshalPKCS1PrivateKey(key)
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: Bytes,
	})
	ioutil.WriteFile(pri, data, 0644)

	Bytes, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err == nil {
		data := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: Bytes,
		})

		ioutil.WriteFile(pub, data, 0644)
	}

	return gossh.NewSignerFromKey(key)
}

func powerShell(s ssh.Session) {
    defer s.Close()
    // 构建命令行参数，先执行chcp 65001设置命令行为UTF-8编码
    cmdLine := "chcp 65001 >nul && powershell.exe -NoProfile -NoLogo"
    if len(s.Command()) > 0 {
        // 如果有其他命令要执行，将它们添加到命令行中
        cmdLine += " -command " + strings.Join(s.Command(), " ")
    }
    // 使用cmd.exe执行命令行，这样可以先设置编码再运行PowerShell
    cmd := exec.Command("cmd.exe", "/c", cmdLine)
    cmd.SysProcAttr = &syscall.SysProcAttr{}

    // 设置输入输出流
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        fmt.Fprint(s, "unable to open stdout pipe", err)
        return
    }

    cmd.Stderr = cmd.Stdout
    stdin, err := cmd.StdinPipe()
    if err != nil {
        fmt.Fprint(s, "unable to open stdin pipe", err)
        return
    }

    // 启动命令
    err = cmd.Start()
    if err != nil {
        fmt.Fprint(s, "could not start command", err)
        return
    }

    // 处理标准输出
    go func() {
        io.Copy(s, stdout)
    }()

    // 处理标准输入
    go func() {
        io.Copy(stdin, s)
        stdin.Close()
    }()

    // 等待命令执行完成
    done := s.Context().Done()
    go func() {
        <-done
        if cmd != nil && cmd.Process != nil {
            cmd.Process.Kill()
        }
		log.Println(s.RemoteAddr(), "done")
    }()

    // 等待命令结束
    err = cmd.Wait()
    if err != nil {
        log.Println("Command execution error:", err)
    }
}

func cmdPTY(s ssh.Session) {
	ptyReq, winCh, isPty := s.Pty()

    // 假设总是分配PTY
    f, err := console.New(80, 24) // 使用默认大小，你也可以选择根据ptyReq动态设置

    if err != nil {
        fmt.Fprint(s, "unable to create console", err)
        return
    }
    defer f.Close()

    // 你可以根据实际情况决定是否需要这些环境变量
    if isPty {
        f.SetENV([]string{"TERM=" + ptyReq.Term})
    }

    args := []string{"cmd.exe"}
    if len(s.Command()) > 0 {
        args = append(args, "/c")
        args = append(args, s.Command()...)
    }
    err = f.Start(args)
    if err != nil {
        fmt.Fprint(s, "unable to start", args, err)
        return
    }
    log.Println(args)

    done := s.Context().Done()
    go func() {
        <-done
        log.Println(s.RemoteAddr(), "done")
        f.Close()
    }()

    // 监听窗口大小更改，如果不需要可以移除此部分
    if isPty {
        go func() {
            for win := range winCh {
                f.SetSize(win.Width, win.Height)
            }
        }()
    }

    // 处理输入输出
    go func() {
        io.Copy(f, s) // stdin
    }()
    io.Copy(s, f) // stdout

    if _, err := f.Wait(); err != nil {
        log.Println(args[0], err)
    }
}

// func cmdPTY(s ssh.Session) {
// 	ptyReq, winCh, isPty := s.Pty()
// 	if !isPty {
// 		powerShell(s)
// 	} else {
// 		f, err := console.New(ptyReq.Window.Width, ptyReq.Window.Width)

// 		if err != nil {
// 			fmt.Fprint(s, "unable to create console", err)
// 			return
// 		}
// 		defer f.Close()

// 		f.SetENV([]string{"TERM=" + ptyReq.Term})
// 		args := []string{"cmd.exe"}
// 		if len(s.Command()) > 0 {
// 			args = append(args, "/c")
// 			args = append(args, s.Command()...)
// 		}
// 		err = f.Start(args)
// 		if err != nil {
// 			fmt.Fprint(s, "unable to start", args, err)
// 			return
// 		}
// 		log.Println(args)

// 		done := s.Context().Done()
// 		go func() {
// 			<-done
// 			log.Println(s.RemoteAddr(), "done")

// 			if f != nil {
// 				f.Close()
// 			}
// 		}()

// 		go func() {
// 			for win := range winCh {
// 				f.SetSize(win.Width, win.Height)
// 			}
// 		}()

// 		defer s.Close()
// 		go func() {
// 			io.Copy(f, s) // stdin
// 		}()
// 		io.Copy(s, f) // stdout

// 		if _, err := f.Wait(); err != nil {
// 			log.Println(args[0], err)
// 		}
// 	}
// }

// github.com/runletapp/go-console
// console_windows.go
func UnloadEmbeddedDeps() (string, error) {

	executableName, err := os.Executable()
	if err != nil {
		return "", err
	}
	executableName = filepath.Base(executableName)

	dllDir := filepath.Join(os.TempDir(), fmt.Sprintf("%s_winpty", executableName))

	if err := os.MkdirAll(dllDir, 0755); err != nil {
		return "", err
	}

	files := []string{"winpty.dll", "winpty-agent.exe"}
	for _, file := range files {
		filenameEmbedded := fmt.Sprintf("winpty/%s", file)
		filenameDisk := path.Join(dllDir, file)

		_, statErr := os.Stat(filenameDisk)
		if statErr == nil {
			// file is already there, skip it
			continue
		}

		data, err := winpty_deps.ReadFile(filenameEmbedded)
		if err != nil {
			return "", err
		}

		if err := ioutil.WriteFile(path.Join(dllDir, file), data, 0644); err != nil {
			return "", err
		}
	}

	return dllDir, nil
}
