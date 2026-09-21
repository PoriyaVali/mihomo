package outbound

import "testing"

func TestMirageCloneIsColdAndRevisionIncludesCredentials(t *testing.T) {
	o := AnyTLSOption{Name: "node", Server: "127.0.0.1", Port: 443, Password: "first", SNI: "example.com"}
	node, err := NewAnyTLS(o)
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	rev := node.MirageRevision()
	clone, err := node.CloneForMirage()
	if err != nil {
		t.Fatal(err)
	}
	defer clone.Close()
	if clone.client == node.client || !clone.option.DisableReuse || clone.option.MinIdleSession != 0 {
		t.Fatal("not a cold clone")
	}
	if node.option.DisableReuse {
		t.Fatal("live node mutated")
	}
	o.Password = "second"
	other, err := NewAnyTLS(o)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if rev == "" || rev == other.MirageRevision() {
		t.Fatal("credentials missing from revision")
	}
}

func TestMirageRejectsNestedDialer(t *testing.T) {
	node, err := NewAnyTLS(AnyTLSOption{BasicOption: BasicOption{DialerProxy: "another"}, Name: "node", Server: "127.0.0.1", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if node.MirageRevision() != "" {
		t.Fatal("unattested nested dialer advertised")
	}
	if clone, err := node.CloneForMirage(); err == nil {
		clone.Close()
		t.Fatal("nested clone accepted")
	}
}
