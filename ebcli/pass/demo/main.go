package main

import (
	"fmt"

	"github.com/lianbaotong/cross2eth/ebcli/pass"
	//"github.com/howeyc/gopass"
	//"os"
	//"syscall"
	//
	//"golang.org/x/term"
)

func main() {
	//fmt.Print("Password: ")
	//bytepw, err := term.ReadPassword(int(syscall.Stdin))
	//if err != nil {
	//	os.Exit(1)
	//}
	//pass := string(bytepw)
	//fmt.Printf("\nYou've entered: %q\n", pass)

	fmt.Printf("Enter silent password: ")
	silentPassword, _ := pass.GetPasswd() // Silent

	// input is in byte and need to convert to string
	// for storing and comparison
	fmt.Println(string(silentPassword))

	fmt.Printf("Enter masked password: ")
	maskedPassword, _ := pass.GetPasswdMasked() // Masked
	fmt.Println(string(maskedPassword))
}
