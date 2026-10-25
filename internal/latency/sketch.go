// Package latency guarda distribuições de latência em buckets logarítmicos com erro relativo de 1%: o valor de um
// quantil difere do real em no máximo 1%, e os resumos se mesclam somando as contagens. O backend (LatencySketch,
// em Java) lê e escreve o mesmo formato binário.
//
// Formato: 0xFE, 0x01, zeros (uvarint), N (uvarint) e N pares (delta do índice em zigzag varint, contagem uvarint).
package latency

import (
	"encoding/binary"
	"errors"
	"math"
	"sort"
)

// RelativeAccuracy é o erro relativo máximo; precisa ser o mesmo nas duas pontas para o merge ser válido.
const RelativeAccuracy = 0.01

const (
	magic   = 0xFE
	version = 1
	// Valores até aqui contam como zero (latência vazia ou negativa).
	minValue = 1e-9
)

var (
	gamma      = (1 + RelativeAccuracy) / (1 - RelativeAccuracy)
	multiplier = 1 / math.Log(gamma)
)

// Sketch é a distribuição. Não é seguro para uso concorrente.
type Sketch struct {
	bins  map[int32]uint64
	zeros uint64
	count uint64
}

// New cria um Sketch vazio.
func New() *Sketch { return &Sketch{bins: map[int32]uint64{}} }

// Add conta um valor (latência em nanos).
func (s *Sketch) Add(value float64) {
	if math.IsNaN(value) {
		return
	}
	s.count++
	if !(value > minValue) {
		s.zeros++
		return
	}
	s.bins[int32(math.Ceil(math.Log(value)*multiplier))]++
}

// Count é o total de valores contados.
func (s *Sketch) Count() uint64 { return s.count }

// Quantile devolve o valor no quantil q (0..1); NaN se vazio ou q fora do intervalo.
func (s *Sketch) Quantile(q float64) float64 {
	if q < 0 || q > 1 || s.count == 0 {
		return math.NaN()
	}
	rank := q * float64(s.count-1)
	if rank < float64(s.zeros) {
		return 0
	}
	seen := float64(s.zeros)
	indexes := s.sortedIndexes()
	for _, index := range indexes {
		seen += float64(s.bins[index])
		if seen > rank {
			return valueOf(index)
		}
	}
	if len(indexes) == 0 {
		return 0
	}
	return valueOf(indexes[len(indexes)-1])
}

// valueOf é o ponto médio relativo do bucket (gamma^(i-1), gamma^i]: o erro é de no máximo RelativeAccuracy.
func valueOf(index int32) float64 { return 2 * math.Pow(gamma, float64(index)) / (gamma + 1) }

func (s *Sketch) sortedIndexes() []int32 {
	indexes := make([]int32, 0, len(s.bins))
	for index := range s.bins {
		indexes = append(indexes, index)
	}
	sort.Slice(indexes, func(a, b int) bool { return indexes[a] < indexes[b] })
	return indexes
}

// MergeWith soma as contagens de other.
func (s *Sketch) MergeWith(other *Sketch) {
	s.zeros += other.zeros
	s.count += other.count
	for index, weight := range other.bins {
		s.bins[index] += weight
	}
}

// Encode serializa no formato binário compartilhado com o backend.
func (s *Sketch) Encode() []byte {
	out := []byte{magic, version}
	out = binary.AppendUvarint(out, s.zeros)
	indexes := s.sortedIndexes()
	out = binary.AppendUvarint(out, uint64(len(indexes)))
	var previous int64
	for _, index := range indexes {
		out = binary.AppendVarint(out, int64(index)-previous)
		out = binary.AppendUvarint(out, s.bins[index])
		previous = int64(index)
	}
	return out
}

// Decode lê o formato de Encode.
func Decode(b []byte) (*Sketch, error) {
	if len(b) < 2 || b[0] != magic || b[1] != version {
		return nil, errors.New("latency: resumo inválido")
	}
	b = b[2:]
	zeros, n := binary.Uvarint(b)
	if n <= 0 {
		return nil, errors.New("latency: resumo truncado")
	}
	b = b[n:]
	bins, n := binary.Uvarint(b)
	if n <= 0 || bins > uint64(len(b)) {
		return nil, errors.New("latency: resumo corrompido")
	}
	b = b[n:]
	s := New()
	s.zeros, s.count = zeros, zeros
	var index int64
	for i := uint64(0); i < bins; i++ {
		delta, n := binary.Varint(b)
		if n <= 0 {
			return nil, errors.New("latency: resumo truncado")
		}
		b = b[n:]
		weight, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("latency: resumo truncado")
		}
		b = b[n:]
		index += delta
		s.bins[int32(index)] += weight
		s.count += weight
	}
	return s, nil
}
