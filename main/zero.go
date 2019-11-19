package main

type Zero func([]byte) (int, error)

func (f Zero) Read(b []byte) (int, error) { return f(b) }

var zero Zero = func(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = byte(0)
	}
	return len(p), nil
}

type FF func([]byte) (int, error)

func (f FF) Read(b []byte) (int, error) { return f(b) }

var ff FF = func(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = byte(255)
	}
	return len(p), nil
}

type F0 func([]byte) (int, error)

func (f F0) Read(b []byte) (int, error) { return f(b) }

var f0 F0 = func(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = byte(240)
	}
	return len(p), nil
}
