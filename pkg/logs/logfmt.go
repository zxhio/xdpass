package logs

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

func appendKeyValue(b *bytes.Buffer, key string, value interface{}) {
	if b.Len() > 0 {
		b.WriteByte(' ')
	}

	b.WriteString(key)
	b.WriteByte('=')
	appendValue(b, value)
}

func appendValue(b *bytes.Buffer, value interface{}) {
	stringVal, ok := value.(string)
	if !ok {
		stringVal = fmt.Sprint(value)
	}

	b.WriteByte('\'')
	b.WriteString(stringVal)
	b.WriteByte('\'')
}

type CustomFormatter struct{}

func (s *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	hpcFormatEntry := func(le *logrus.Entry, bb *bytes.Buffer) {
		for k, v := range le.Data {
			appendKeyValue(bb, k, v)
		}
	}

	return format(entry, hpcFormatEntry)
}

type EntryPair struct {
	Key   string
	Value interface{}
}

type entryPairSlice []EntryPair

func (e entryPairSlice) Len() int           { return len(e) }
func (e entryPairSlice) Swap(i, j int)      { e[i], e[j] = e[j], e[i] }
func (e entryPairSlice) Less(i, j int) bool { return e[i].Key < e[j].Key }

func OrderFields(entry *logrus.Entry) []EntryPair {
	entryList := []EntryPair{}
	for k, v := range entry.Data {
		entryList = append(entryList, EntryPair{
			Key:   k,
			Value: v,
		})
	}

	sort.Sort(entryPairSlice(entryList))
	return entryList
}

type CustomOrderFormatter struct{}

func (s *CustomOrderFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	orderFields := func(le *logrus.Entry, bb *bytes.Buffer) {
		entryList := OrderFields(le)
		for _, entry := range entryList {
			appendKeyValue(bb, entry.Key, entry.Value)
		}
	}

	return format(entry, orderFields)
}

func format(entry *logrus.Entry, formatEntry func(*logrus.Entry, *bytes.Buffer)) ([]byte, error) {
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	b.WriteString(strings.ToUpper(entry.Level.String())[:4])
	b.WriteByte(' ')
	b.WriteString(time.Now().Local().Format("20060102 15:04:05"))

	if entry.Caller != nil {
		b.WriteByte(' ')
		b.WriteString(entry.Caller.File)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(entry.Caller.Line))
	}

	b.WriteString(" msg='")
	b.WriteString(strings.TrimRight(entry.Message, "\n"))
	b.WriteByte('\'')

	formatEntry(entry, b)

	b.WriteByte('\n')

	return b.Bytes(), nil
}
