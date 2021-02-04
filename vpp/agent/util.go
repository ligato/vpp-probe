package agent

import (
	"fmt"
	"strconv"
)

func toInt(v interface{}) int {
	s := fmt.Sprint(v)
	idx, _ := strconv.Atoi(s)
	return idx
}

func toBool(v interface{}) bool {
	s := fmt.Sprint(v)
	idx, _ := strconv.ParseBool(s)
	return idx
}
