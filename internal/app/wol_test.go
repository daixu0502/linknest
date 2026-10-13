package app

import (
	"strings"
	"testing"
)

func TestWOLMACCompatibility(t *testing.T) {
	const want = "02:AB:CD:EF:12:34"
	for _, input := range []string{
		want, "02-ab-cd-ef-12-34", "02abcdef1234", "02ab.cdef.1234",
		" 02:ab:cd:ef:12:34\r\n", "02 AB CD EF 12 34",
		"02：AB：CD：EF：12：34", "02－AB－CD－EF－12－34",
		"02–AB–CD–EF–12–34", "02‑AB‑CD‑EF‑12‑34",
		"\ufeff02:AB:\u200bCD:EF:12:34\u00a0", "02ab．cdef．1234",
	} {
		t.Run(input, func(t *testing.T) {
			mac, err := parseWOLMAC(input)
			if err != nil || strings.ToUpper(mac.String()) != want {
				t.Fatalf("parse %q: %v / %v", input, mac, err)
			}
			c := Config{Devices: []Device{{ID: "test-device", Name: "test", MAC: input, Broadcast: "192.0.2.255"}}}
			if err := validate(c, "127.0.0.1:17880"); err != nil {
				t.Fatal(err)
			}
			migrateConfig(&c)
			if c.Devices[0].MAC != want {
				t.Fatal("not canonical", c.Devices[0].MAC)
			}
		})
	}
	for _, input := range []string{"", "02:AB:CD:EF:12", "02:AB:CD:EF:12:34:56:78", "02:AB:CD:EF:12:GG", "2:AB:CD:EF:12:34", "02:AB:CD:EF:12:34;reboot", "02/AB/CD/EF/12/34", "0x02abcdef1234"} {
		if _, err := parseWOLMAC(input); err == nil {
			t.Errorf("accepted malformed address %q", input)
		}
	}
}

func TestWOLConfigAPIStoresCanonicalMAC(t *testing.T) {
	a := testApp(t)
	ck := signIn(t, a)
	c := a.store.snapshot()
	c.Devices = []Device{{ID: "wol-test", Name: " Workstation ", MAC: "\ufeff02－ab－cd－ef－12－34 ", Broadcast: " 192.0.2.255 "}}
	if w := request(a, "PUT", "/api/config", c, ck); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	s, err := newStore(a.store.dir)
	if err != nil {
		t.Fatal(err)
	}
	d := s.snapshot().Devices[0]
	if d.MAC != "02:AB:CD:EF:12:34" || d.Name != "Workstation" || d.Broadcast != "192.0.2.255" {
		t.Fatalf("unexpected persisted device: %+v", d)
	}
	c.Devices[0].MAC = "invalid"
	if w := request(a, "PUT", "/api/config", c, ck); w.Code != 400 {
		t.Fatal("malformed MAC accepted", w.Code)
	}
	if a.store.snapshot().Devices[0] != d {
		t.Fatal("invalid request changed stored device")
	}
}
