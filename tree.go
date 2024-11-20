// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.

package nradix

import (
	"errors"
	"net"
	"strings"
)

var fullMask net.IPMask

func init() {
	fullMask = net.CIDRMask(128, 128)
}

type node struct {
	left, right, parent *node
	value               interface{}
}

// Tree implements radix tree for working with IP/mask. Thread safety is not guaranteed, you should choose your own style of protecting safety of operations.
type Tree struct {
	root *node
	free *node

	alloc []node
}

const (
	startbit  = uint32(0x80000000)
	startbyte = byte(0x80)
)

var (
	ErrNodeBusy = errors.New("Node Busy")
	ErrNotFound = errors.New("No Such Node")
	ErrBadIP    = errors.New("Bad IP address or mask")
)

// NewTree creates Tree and preallocates (if preallocate not zero) number of nodes that would be ready to fill with data.
func NewTree(preallocate int) *Tree {
	tree := new(Tree)
	tree.root = tree.newnode()
	if preallocate == 0 {
		return tree
	}

	return tree
}

// AddCIDR adds value associated with IP/mask to the tree. Will return error for invalid CIDR or if value already exists.
func (tree *Tree) AddCIDR(cidr string, val interface{}) error {
	ip, mask, err := parsecidr(cidr)
	if err != nil {
		return err
	}
	return tree.insert(ip, mask, val, false)
}

func (tree *Tree) AddCIDRb(cidr []byte, val interface{}) error {
	return tree.AddCIDR(string(cidr), val)
}

// AddCIDR adds value associated with IP/mask to the tree. Will return error for invalid CIDR or if value already exists.
func (tree *Tree) SetCIDR(cidr string, val interface{}) error {
	ip, mask, err := parsecidr(cidr)
	if err != nil {
		return err
	}
	return tree.insert(ip, mask, val, true)
}

func (tree *Tree) SetCIDRb(cidr []byte, val interface{}) error {
	return tree.SetCIDR(string(cidr), val)
}

// DeleteWholeRangeCIDR removes all values associated with IPs
// in the entire subnet specified by the CIDR.
func (tree *Tree) DeleteWholeRangeCIDR(cidr string) error {
	ip, mask, err := parsecidr(cidr)
	if err != nil {
		return err
	}

	return tree.delete(ip, mask, true)
}

func (tree *Tree) DeleteWholeRangeCIDRb(cidr []byte) error {
	return tree.DeleteWholeRangeCIDR(string(cidr))
}

// DeleteCIDR removes value associated with IP/mask from the tree.
func (tree *Tree) DeleteCIDR(cidr string) error {
	ip, mask, err := parsecidr(cidr)
	if err != nil {
		return err
	}
	return tree.delete(ip, mask, false)
}

func (tree *Tree) DeleteCIDRb(cidr []byte) error {
	return tree.DeleteCIDR(string(cidr))
}

// Find CIDR traverses tree to proper Node and returns previously saved information in longest covered IP.
func (tree *Tree) FindCIDR(cidr string) (interface{}, error) {
	ip, mask, err := parsecidr(cidr)
	if err != nil {
		return nil, err
	}
	return tree.find(ip, mask), nil
}

func (tree *Tree) FindCIDRb(cidr []byte) (interface{}, error) {
	return tree.FindCIDR(string(cidr))
}

func (tree *Tree) insert(key net.IP, mask net.IPMask, value interface{}, overwrite bool) error {
	if len(key) != len(mask) {
		return ErrBadIP
	}

	var i int
	bit := startbyte
	node := tree.root
	next := tree.root
	for bit&mask[i] != 0 {
		if key[i]&bit != 0 {
			next = node.right
		} else {
			next = node.left
		}
		if next == nil {
			break
		}

		node = next

		if bit >>= 1; bit == 0 {
			if i++; i == len(key) {
				break
			}
			bit = startbyte
		}

	}
	if next != nil {
		if node.value != nil && !overwrite {
			return ErrNodeBusy
		}
		node.value = value
		return nil
	}

	for bit&mask[i] != 0 {
		next = tree.newnode()
		next.parent = node
		if key[i]&bit != 0 {
			node.right = next
		} else {
			node.left = next
		}
		node = next
		if bit >>= 1; bit == 0 {
			if i++; i == len(key) {
				break
			}
			bit = startbyte
		}
	}
	node.value = value

	return nil
}

func (tree *Tree) delete(key net.IP, mask net.IPMask, wholeRange bool) error {
	if len(key) != len(mask) {
		return ErrBadIP
	}

	var i int
	bit := startbyte
	node := tree.root
	for node != nil && bit&mask[i] != 0 {
		if key[i]&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}
		if bit >>= 1; bit == 0 {
			if i++; i == len(key) {
				break
			}
			bit = startbyte
		}
	}
	if node == nil {
		return ErrNotFound
	}

	if !wholeRange && (node.right != nil || node.left != nil) {
		// keep it just trim value
		if node.value != nil {
			node.value = nil
			return nil
		}
		return ErrNotFound
	}

	// need to trim leaf
	for {
		if node.parent.right == node {
			node.parent.right = nil
		} else {
			node.parent.left = nil
		}
		// reserve this node for future use
		node.right = tree.free
		tree.free = node

		// move to parent, check if it's free of value and children
		node = node.parent
		if node.right != nil || node.left != nil || node.value != nil {
			break
		}
		// do not delete root node
		if node.parent == nil {
			break
		}
	}

	return nil
}

func (tree *Tree) find(key net.IP, mask net.IPMask) (value interface{}) {
	if len(key) != len(mask) {
		return ErrBadIP
	}
	var i int
	bit := startbyte
	node := tree.root
	for node != nil {
		if node.value != nil {
			value = node.value
		}
		if key[i]&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}
		if mask[i]&bit == 0 {
			break
		}
		if bit >>= 1; bit == 0 {
			i, bit = i+1, startbyte
			if i >= len(key) {
				// reached depth of the tree, there should be matching node...
				if node != nil {
					value = node.value
				}
				break
			}
		}
	}
	return value
}

func (tree *Tree) newnode() (p *node) {
	if tree.free != nil {
		p = tree.free
		tree.free = tree.free.right

		// release all prior links
		p.right = nil
		p.parent = nil
		p.left = nil
		p.value = nil
		return p
	}

	ln := len(tree.alloc)
	if ln == cap(tree.alloc) {
		// filled one row, make bigger one
		tree.alloc = make([]node, ln+200)[:1] // 200, 600, 1400, 3000, 6200, 12600 ...
		ln = 0
	} else {
		tree.alloc = tree.alloc[:ln+1]
	}
	return &(tree.alloc[ln])
}

func parsecidr(cidr string) (net.IP, net.IPMask, error) {
	p := strings.IndexByte(cidr, '/')
	if p == -1 {
		ip := net.ParseIP(cidr)
		return ip.To16(), fullMask, nil
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}

	prefixLength, _ := ipNet.Mask.Size()
	if strings.IndexByte(cidr, '.') > 0 {
		prefixLength += 96
	}
	mask := net.CIDRMask(prefixLength, 128)

	return ip.To16(), mask, nil
}