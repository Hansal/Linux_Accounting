package monitors

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	r "riemann"
)

const (
	minUid = 100
	maxUid = 9999
)

func init() {
	Register("sockets", NewSockets)
}

func NewSockets(decoder *json.Decoder) ([]Monitor, error) {
	return []Monitor{Monitor{runner: &Runner{new(ProcMonitor)}}}, nil
}

// Data Stucture for each user id
type mystruct struct {
	username       string
	pid            []string
	known          int
	openfiles      int
	hash_tcpstates map[string]int
	hash_inode     map[string]int
}

// Data Stucture for unix
type unix struct {
	inode string
	found bool
}

// Data Stucture to get new instance everytime you run main function. So there i sno memory leak
type ProcMonitor struct {
	hash_uid   map[int]*mystruct
	unix_inode []unix
}

var re = regexp.MustCompile("\\[\\d+\\]")

// Mapping from Flags to TCP states
func switch_case(s string) string {
	switch s {

	case "01":
		return "established"
	case "02":
		return "syn_sent"
	case "03":
		return "syn_recv"
	case "04":
		return "fin_wait1"
	case "05":
		return "fin_wait2"
	case "06":
		return "time_wait"
	case "07":
		return "close"
	case "08":
		return "close_wait"
	case "09":
		return "last_ack"
	case "0A":
		return "listen"
	case "0B":
		return "closing"
	case "0C":
		return "closed"
	default:
		return "error"
	}
}

// Read from /proc/net/unix and create an array of struct {unix inodes, boolean value}
func (m *ProcMonitor) unix() error {

	// Format
	// Num       RefCount Protocol Flags    Type St Inode Path
	// ffff880077748a80: 00000002 00000000 00010000 0001 01  2819 /var/run/acpid.socket
	// ffff880036409c00: 00000002 00000000 00010000 0001 01  3878 /var/run/dbus/system_bus_socket
	// ffff88007774cd00: 00000002 00000000 00010000 0005 01  2375 /run/udev/control
	// ffff88007774aa00: 00000002 00000000 00010000 0001 01  2284 @/com/ubuntu/upstart
	// ffff88007b17f000: 0000000C 00000000 00000000 0002 01 11238 /dev/log

	dat, err := ioutil.ReadFile("/proc/net/unix")
	if err != nil {
		return err
	}
	lines := strings.Split(string(dat), "\n")
	lines = lines[1:]
	for _, j := range lines {
		if len(j) != 0 {
			line := strings.Fields(j)
			members := unix{line[6], false}
			m.unix_inode = append(m.unix_inode, members)
		}
	}
	return nil
}

// Gives a count of open file descriptors
func (m *ProcMonitor) count_fd(pid string, uid int, username string) (int, error) {

	temp := "/proc/"
	temp += pid
	temp += "/fd"

	// Format
	// lrwx------ 1 root root 64 Jun 18 19:33 25 -> socket:[3788798698]
	// lrwx------ 1 root root 64 Jun 18 19:33 26 -> socket:[3788798699]
	// lrwx------ 1 root root 64 Jun 18 19:33 27 -> socket:[4113852661]
	// lrwx------ 1 root root 64 Jun 18 19:33 28 -> socket:[4113837928]
	// lrwx------ 1 root root 64 Jun 18 19:33 29 -> socket:[3788804118]

	out, err := exec.Command("ls", temp, "-fl").Output()
	if err != nil {
		return 0, err
	}
	fd := strings.Split(string(out), "\n")
	for _, j := range fd {
		// Get the inode and Hash map it. Also check the inode if it is there in unix inode and change the boolean value accoringly
		if strings.Contains(j, username) && strings.Contains(j, "-> socket") {
			match1 := re.FindStringSubmatch(j)
			ino := (match1[0][1 : len(match1[0])-1])
			elem, ok := m.hash_uid[uid].hash_inode[ino]
			if ok == false {
				m.hash_uid[uid].hash_inode[ino] = 1
			} else {
				m.hash_uid[uid].hash_inode[ino] = elem + 1
			}
			// To check for unix inode
			for index, value := range m.unix_inode {
				if ino == value.inode && !value.found {
					m.hash_uid[uid].known += 1
					m.unix_inode[index].found = true
				}
			}
		}
	}
	return (len(fd) - 3), nil
}

// Read /proc/net/tcp and /proc/net/tcp6. Compare the inodes for each uid using Hash Map. Use the switch case to get final TCP states
func (m *ProcMonitor) tcp_states() error {

	//  Format
	//  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
	// 0: 476036C6:A1C2 191E1EAC:C7B0 03 00000000:00000000 01:000000D6 00000003   703        0 0 2 0000000000000000
	// 1: 00000000:0562 00000000:0000 0A 00000000:00000000 00:00000000 00000000  5009        0 276725449 1 0000000000000000 100 0 0 10 0
	// 2: 00000000:1622 00000000:0000 0A 00000000:00000000 00:00000000 00000000   104        0 4145859344 1 0000000000000000 100 0 0 10 0

	dat4, err4 := ioutil.ReadFile("/proc/net/tcp")
	if err4 != nil {
		return err4
	}
	lines4 := strings.Split(string(dat4), "\n")
	lines4 = lines4[1:]
	for _, j := range lines4 {
		if len(j) != 0 {
			line4 := strings.Fields(j)
			uid, err := strconv.Atoi(line4[7])
			if err != nil {
				return err
			}
			// Increment the count of known socket values and also use switch case to convert flag to TCP state {0A: ESTABLISHED}
			if _, ok := m.hash_uid[uid]; ok {
				if _, okay := m.hash_uid[uid].hash_inode[line4[9]]; okay {
					m.hash_uid[uid].known += 1
				}
				if elem, ok4 := m.hash_uid[uid].hash_tcpstates[switch_case(line4[3])]; !ok4 {
					m.hash_uid[uid].hash_tcpstates[switch_case(line4[3])] = 1
				} else {
					m.hash_uid[uid].hash_tcpstates[switch_case(line4[3])] = elem + 1
				}
			}

		}
	}

	//  Format
	//  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
	// 0: 00000000000000000000000000000000:1E5B 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   123        0 1063773884 1 0000000000000000 100 0 0 10 -1
	// 1: 00000000000000000000000000000000:115C 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2522370923 1 0000000000000000 100 0 0 10 -1

	dat6, err6 := ioutil.ReadFile("/proc/net/tcp6")
	if err6 != nil {
		return err6
	}
	lines6 := strings.Split(string(dat6), "\n")
	lines6 = lines6[1:]
	for _, j := range lines6 {
		if len(j) != 0 {
			line6 := strings.Fields(j)
			uid, err := strconv.Atoi(line6[7])
			if err != nil {
				return err
			}
			// Increment the count of known socket values and also use switch case to convert flag to TCP state {0A: ESTABLISHED}
			if _, ok := m.hash_uid[uid]; ok {
				if _, okay := m.hash_uid[uid].hash_inode[line6[9]]; okay {
					m.hash_uid[uid].known += 1
				}
				if elem, ok6 := m.hash_uid[uid].hash_tcpstates[switch_case(line6[3])]; !ok6 {
					m.hash_uid[uid].hash_tcpstates[switch_case(line6[3])] = 1
				} else {
					m.hash_uid[uid].hash_tcpstates[switch_case(line6[3])] = elem + 1
				}
			}

		}
	}
	return nil
}

func (m *ProcMonitor) Run() error {

	// Call unix function to get unix inodes
	m.hash_uid = make(map[int]*mystruct)
	error := m.unix()
	if error != nil {
		return error
	}
	// Format: ps -eo uid,user:30,pid
	// UID USER                             PID
	// 102 messagebus                       923
	// 101 syslog                           985
	// 5078 bsekulic                        1063
	// 5078 bsekulic                        1067

	dat, err := exec.Command("ps", "-eo", "uid,user:30,pid").Output()
	if err != nil {
		return err
	}
	words := strings.Fields(string(dat))
	// Created a map where the key is uid and the value is a data structure (username,pid,states,known,etc)
	for i := 3; i < len(words); i += 3 {
		uid, _ := strconv.Atoi(words[i])
		_, ok := m.hash_uid[uid]
		if !ok && ((uid > minUid && uid < maxUid) || uid == 33) {
			test := &mystruct{words[i+1], []string{words[i+2]}, 0, 0, make(map[string]int), make(map[string]int)}
			m.hash_uid[uid] = test
		} else if (uid > minUid && uid < maxUid) || uid == 33 {
			m.hash_uid[uid] = &mystruct{m.hash_uid[uid].username, append(m.hash_uid[uid].pid, words[i+2]), 0, 0, make(map[string]int), make(map[string]int)}
		}
	}
	for key, value := range m.hash_uid {
		for i := 0; i < len(value.pid); i++ {
			counts, err := m.count_fd(value.pid[i], key, value.username)
			if err != nil {
				return err
			}
			m.hash_uid[key].openfiles += counts
		}
	}

	// Call tcpstates function to get the socket known value and also the TCP state
	m.tcp_states()

	// Print the final statistics
	for _, value := range m.hash_uid {
		r.Emit(fmt.Sprintf("cyclops users %s openfiles", value.username), value.openfiles)
		r.Emit(fmt.Sprintf("cylops sockstat counts users %s sockets known", value.username), value.known)
		r.Emit(fmt.Sprintf("cylops sockstat counts users %s sockets unknown", value.username), len(value.hash_inode)-value.known)
		for state, num := range value.hash_tcpstates {
			r.Emit(fmt.Sprintf("cyclops users %s tcp %v", value.username, state), num)
		}
	}
	return nil
}
