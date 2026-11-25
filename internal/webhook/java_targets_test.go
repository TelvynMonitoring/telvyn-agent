package webhook

import (
	"reflect"
	"testing"
)

func TestJavaTargets(t *testing.T) {
	cases := []struct {
		name string
		in   []container
		want []int
	}{
		{"imagem com palavra-chave Java", []container{{Image: "registry/marketplace-java:1"}}, []int{0}},
		{"imagem sem palavra-chave, container único", []container{{Image: "webgoat/webgoat:v2026.5"}}, []int{0}},
		{"vários containers, só um reconhecido", []container{{Image: "nginx"}, {Image: "eclipse-temurin:21"}}, []int{1}},
		{"vários containers, nenhum reconhecido: não adivinha", []container{{Image: "nginx"}, {Image: "app/x"}}, []int{}},
		{"nenhum container", nil, []int{}},
	}
	for _, c := range cases {
		if got := javaTargets(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: javaTargets = %v, quer %v", c.name, got, c.want)
		}
	}
}
