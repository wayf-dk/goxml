package goxml

import (
	"C"
	"fmt"
	"strings"

	"github.com/wayf-dk/go-libxml2/types"
)

// RmElement removes an element in a Node
func RmElement(element types.Node) {
	libxml2Lock.Lock()
	defer libxml2Lock.Unlock()
	parent, _ := element.ParentNode()
	parent.RemoveChild(element)
	element.Free()
}

func walk(n types.Node, level int) (pp string) {
	switch n := n.(type) {
	case types.Element:
		tag := n.NodeName()
		attrs := []string{}
		namespaces, _ := n.GetNamespaces()
		for _, ns := range namespaces {
			prefix := "xmlns"
			if ns.Prefix() != "" {
				prefix = prefix + ":" + ns.Prefix()
			}
			attrs = append(attrs, prefix+"=\""+ns.URI()+"\"")
		}

		attributes, _ := n.Attributes()
		for _, ats := range attributes {
			attrs = append(attrs, strings.TrimSpace(ats.String()))
		}
		l := len(attrs)
		x := ""
		if l == 0 {
			//x = ">"
		} else if l > 0 {
			x = " " + attrs[0]
			attrs = attrs[1:]
			if l == 1 {
				//x += ">"
			}
			l--
		}

		pp = fmt.Sprintf("%*s<%s%s", level*4, "", tag, x)
		x = ""
		for i, attr := range attrs {
			newline1 := "\n"
			if i == l-1 {
				//x = ">"
				newline1 = ""
			}
			newline := ""
			if i == 0 {
				newline = "\n"
			}
			pp += fmt.Sprintf("%s%*s%s%s%s", newline, level*4+2+len(tag), "", attr, x, newline1)
		}
		children, _ := n.ChildNodes()
		elements := false
		subpp := ""
		for _, c := range children {
			_, ok := c.(types.Element)
			elements = elements || ok
			subpp += walk(c, level+1)
		}
		if elements {
			pp += fmt.Sprintf(">\n%s%*s</%s>\n", subpp, level*4, "", n.NodeName())
		} else {
			if subpp == "" {
				pp += "/>\n"
			} else {
				pp += fmt.Sprintf(">\n%*s%s\n%*s</%s>\n", level*5, "", subpp, level*4, "", n.NodeName())
			}
		}
	case types.Node:
		if txt := strings.TrimSpace(n.TextContent()); txt != "" {
			pp = txt
		}
	}
	return
}
