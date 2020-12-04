package agent

import "fmt"

type Colorer interface {
	Code() string
}

func escapeClr(c Colorer, s interface{}) string {
	return fmt.Sprintf("\xff\x1b[%sm\xff%v\xff\x1b[0m\xff", c.Code(), s)
}
