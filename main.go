package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"io"
	"log"
	"math"
	mRand "math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	qrcodeTerminal "github.com/Baozisoftware/qrcode-terminal-go"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cretz/bine/tor"
	"github.com/liyue201/goqr"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// ============================================================================
// CONFIGURATION MANAGEMENT SECTION
// ============================================================================

// Config holds all application configuration
type Config struct {
	// User Configuration
	User    string `mapstructure:"user"`
	Verbose bool   `mapstructure:"verbose"`

	// Tor Configuration
	Tor TorConfig `mapstructure:"tor"`

	// Security Configuration
	Security SecurityConfig `mapstructure:"security"`

	// Network Configuration
	Network NetworkConfig `mapstructure:"network"`

	// File Configuration
	Files FileConfig `mapstructure:"files"`

	// Padding Configuration
	Padding PaddingConfig `mapstructure:"padding"`
}

type TorConfig struct {
	Port                  int           `mapstructure:"port"`
	DialTimeout           time.Duration `mapstructure:"dial_timeout"`
	HSTimeout             time.Duration `mapstructure:"hs_timeout"`
	CircuitRotateInterval time.Duration `mapstructure:"circuit_rotate_interval"`
	DataDir               string        `mapstructure:"data_dir"`
}

type SecurityConfig struct {
	KeyRotationInterval       time.Duration `mapstructure:"key_rotation_interval"`
	MaxMessagesBeforeRotation int           `mapstructure:"max_messages_before_rotation"`
	HMACSize                  int           `mapstructure:"hmac_size"`
	SequenceWindowSize        int           `mapstructure:"sequence_window_size"`
}

type NetworkConfig struct {
	HeartbeatInterval    time.Duration `mapstructure:"heartbeat_interval"`
	HeartbeatTimeout     time.Duration `mapstructure:"heartbeat_timeout"`
	DummyTrafficInterval time.Duration `mapstructure:"dummy_traffic_interval"`
	MaxDummyPackets      int           `mapstructure:"max_dummy_packets"`
	JitterRangeMs        int           `mapstructure:"jitter_range_ms"`
}

type FileConfig struct {
	FriendsFilename string `mapstructure:"friends_filename"`
	ConfigDir       string `mapstructure:"config_dir"`
}

type PaddingConfig struct {
	MinSize        int  `mapstructure:"min_size"`
	MaxSize        int  `mapstructure:"max_size"`
	DefaultSize    int  `mapstructure:"default_size"`
	DynamicPadding bool `mapstructure:"dynamic_padding"`
	JitterEnabled  bool `mapstructure:"jitter_enabled"`
	DummyTraffic   bool `mapstructure:"dummy_traffic"`
	AdaptiveSize   bool `mapstructure:"adaptive_size"`
}

// loadConfig initializes viper and loads configuration from multiple sources
func loadConfig() (*Config, error) {
	v := viper.New()

	// Set configuration file properties
	v.SetConfigName("pmessenger")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")
	v.AddConfigPath("$HOME/.pmessenger")

	// Set environment variable properties
	v.AutomaticEnv()
	v.SetEnvPrefix("PMESSENGER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set default values
	setConfigDefaults(v)

	// Read config file if it exists
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		log.Println("No config file found, using defaults and environment variables")
	}

	// Bind command line flags
	bindFlags(v)

	// Parse flags
	pflag.Parse()

	// Validate required configuration
	if err := validateConfig(v); err != nil {
		return nil, err
	}

	// Unmarshal into config struct
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	currentPath, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %w", err)
	}

	// Set computed values
	if config.Tor.DataDir == "" {
		config.Tor.DataDir = filepath.Join(currentPath, config.Files.ConfigDir, config.User)
	}

	return &config, nil
}

func setConfigDefaults(v *viper.Viper) {
	// Tor defaults
	v.SetDefault("tor.port", 11009)
	v.SetDefault("tor.dial_timeout", "45s")
	v.SetDefault("tor.hs_timeout", "30s")
	v.SetDefault("tor.circuit_rotate_interval", "5m")

	// Security defaults
	v.SetDefault("security.key_rotation_interval", "1h")
	v.SetDefault("security.max_messages_before_rotation", 50)
	v.SetDefault("security.hmac_size", 32)
	v.SetDefault("security.sequence_window_size", 1000)

	// Network defaults
	v.SetDefault("network.heartbeat_interval", "30s")
	v.SetDefault("network.heartbeat_timeout", "75s")
	v.SetDefault("network.dummy_traffic_interval", "15s")
	v.SetDefault("network.max_dummy_packets", 3)
	v.SetDefault("network.jitter_range_ms", 500)

	// File defaults
	v.SetDefault("files.friends_filename", "friends.json")
	v.SetDefault("files.config_dir", ".tor-messenger")

	// Padding defaults
	v.SetDefault("padding.min_size", 128)
	v.SetDefault("padding.max_size", 8192)
	v.SetDefault("padding.default_size", 1024)
	v.SetDefault("padding.dynamic_padding", true)
	v.SetDefault("padding.jitter_enabled", true)
	v.SetDefault("padding.dummy_traffic", true)
	v.SetDefault("padding.adaptive_size", true)

	// Application defaults
	v.SetDefault("verbose", false)
}

func bindFlags(v *viper.Viper) {
	pflag.String("user", "", "Your username (required)")
	pflag.Bool("verbose", false, "Enable verbose Tor logging")
	pflag.Duration("circuit-rotate-interval", 5*time.Minute, "Tor circuit rotation interval")
	pflag.String("config", "", "Path to config file")

	v.BindPFlag("user", pflag.Lookup("user"))
	v.BindPFlag("verbose", pflag.Lookup("verbose"))
	v.BindPFlag("tor.circuit_rotate_interval", pflag.Lookup("circuit-rotate-interval"))

	if configPath := pflag.Lookup("config"); configPath != nil && configPath.Value.String() != "" {
		v.SetConfigFile(configPath.Value.String())
	}
}

func validateConfig(v *viper.Viper) error {
	if v.GetString("user") == "" {
		return fmt.Errorf("user is required (use --user flag or PMESSENGER_USER env var)")
	}
	return nil
}

// ============================================================================
// CONSTANTS AND GLOBALS
// ============================================================================

const (
	Version      = "v3.5.0"
	ProtocolInfo = "TorMessenger"
)

var (
	adverbs = []string{
		"ably", "abusively", "actually", "annoyingly", "anxiously", "arrogantly",
		"awkwardly", "badly", "bashfully", "beautifully", "bleakly", "blissfully",
		"boldly", "bravely", "briefly", "brightly", "briskly", "broadly", "busily",
		"calmly", "carefully", "carelessly", "cautiously", "cheerfully", "clearly",
		"cleverly", "closely", "clumsily", "coaxingly", "colorfully", "coolly",
		"courageously", "craftily", "creatively", "curiously", "daily", "dearly",
		"deftly", "deliberately", "delightfully", "diligently", "discreetly",
		"eagerly", "easily", "elegantly", "energetically", "enthusiastically",
		"equally", "excitedly", "faithfully", "fearlessly", "fiercely", "fondly",
		"foolishly", "frankly", "freely", "generously", "gently", "gladly",
		"gracefully", "gratefully", "happily", "hardly", "harmoniously", "hastily",
		"healthily", "helpfully", "honestly", "hopelessly", "humbly", "impressively",
		"indifferently", "innocently", "intensely", "intently", "interestingly",
		"jovially", "joyfully", "jubilantly", "justly", "keenly", "kindly",
		"knowingly", "lazily", "lightly", "likeably", "lovingly", "loyally",
		"loudly", "lovably", "luckily", "merrily", "mindfully", "modestly",
		"naturally", "neatly", "nicely", "nimbly", "nobly", "obediently",
	}
	adjectives = []string{
		"able", "abnormal", "above", "absent", "absolute", "abstract", "absurd",
		"academic", "acceptable", "accessible", "accurate", "active", "actual",
		"acute", "additional", "adequate", "adjacent", "administrative", "adult",
		"adverse", "advisory", "aerial", "aesthetic", "afraid", "aggregate",
		"aggressive", "agricultural", "alert", "alien", "alive", "alone", "alright",
		"alternative", "amazing", "ambitious", "ample", "ancient", "angry", "annual",
		"anxious", "apparent", "appropriate", "architectural", "arguable", "armed",
		"aromatic", "artificial", "artistic", "ashamed", "assertive", "assured",
		"astonishing", "athletic", "attractive", "authentic", "automatic", "awesome",
		"awkward", "balanced", "basic", "beautiful", "beneficial", "big", "bitter",
		"bizarre", "bold", "brave", "bright", "brilliant", "broad", "busy",
		"calm", "capable", "careful", "caring", "cautious", "central", "certain",
		"challenging", "charming", "cheap", "cheerful", "chief", "civil", "classic",
		"clean", "clear", "clever", "close", "coarse", "cold", "colorful", "comfortable",
		"common", "compact", "competent", "competitive", "complete", "complex",
		"comprehensive", "concise", "confident", "conscious", "consistent", "constant",
		"constructive", "content", "continuous", "convenient", "cool", "cooperative",
		"correct", "costly", "courageous", "courteous", "creative", "credible",
		"critical", "crucial", "curious", "current", "customary", "cute", "daily",
		"damaged", "dangerous", "dark", "deadly", "decent", "decisive", "deep",
	}
	animals = []string{
		"alligator", "ant", "bear", "bee", "bird", "camel", "cat", "cheetah", "chicken",
		"chimpanzee", "cow", "crocodile", "deer", "dog", "dolphin", "duck", "eagle",
		"ferret", "finch", "flamingo", "fox", "frog", "gazelle", "giraffe", "goat",
		"goldfish", "hamster", "hedgehog", "hippopotamus", "horse", "kangaroo",
		"koala", "lion", "lobster", "monkey", "octopus", "otter", "owl", "panda",
		"parrot", "penguin", "pig", "pigeon", "rabbit", "rat", "reindeer", "seal",
		"shark", "sheep", "snail", "snake", "spider", "squirrel", "tiger", "tortoise",
		"elephant", "fish", "fly", "fox", "frog", "giraffe", "goat", "goldfish",
		"hamster", "hippopotamus", "horse", "kangaroo", "kitten", "lion", "lobster",
		"monarch", "mouse", "mule", "newt", "octopus", "orangutan", "ostrich",
		"otter", "owl", "panda", "parrot", "penguin", "piglet",
		"pigeon", "porcupine", "rabbit", "raccoon", "rat", "reindeer", "rooster",
		"salmon", "scorpion", "seahorse", "seal", "shark", "sheep", "shrimp",
		"snail", "snake", "spider", "squid", "squirrel", "starfish", "stingray",
		"tiger", "toad", "tortoise", "toucan", "turkey", "turtle", "vulture",
		"walrus", "wasp", "weasel", "whale", "wolf", "wombat", "zebra", "zebu",
		"monkey", "octopus", "owl", "panda", "pig", "puppy", "rabbit", "rat", "scorpion",
		"seal", "shark", "sheep", "snail", "snake", "spider", "squirrel", "tiger",
		"turtle", "wolf", "zebra", "zebu", "zorse", "zucchini",
	}
)

// ============================================================================
// SECURITY AND CRYPTO SECTION
// ============================================================================

type SecureBuffer struct {
	data   []byte
	locked bool
	mutex  sync.Mutex
	wiped  bool
}

func NewSecureBuffer(size int) (*SecureBuffer, error) {
	data := make([]byte, size)
	sb := &SecureBuffer{
		data: data,
	}

	if err := sb.Lock(); err != nil {
		log.Printf("Warning: Could not lock memory: %v", err)
	}

	return sb, nil
}

func (sb *SecureBuffer) Lock() error {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	if sb.locked || len(sb.data) == 0 {
		return nil
	}

	ptr := uintptr(unsafe.Pointer(&sb.data[0]))
	length := uintptr(len(sb.data))

	pageSize := uintptr(os.Getpagesize())
	alignedPtr := ptr & ^(pageSize - 1)
	alignedLength := ((ptr + length - alignedPtr + pageSize - 1) / pageSize) * pageSize

	r1, _, _ := syscall.Syscall(syscall.SYS_MLOCK, alignedPtr, alignedLength, 0)
	if r1 != 0 {
		return syscall.Errno(r1)
	}

	sb.locked = true
	return nil
}

func (sb *SecureBuffer) Unlock() error {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	if !sb.locked || len(sb.data) == 0 {
		return nil
	}

	ptr := uintptr(unsafe.Pointer(&sb.data[0]))
	length := uintptr(len(sb.data))

	pageSize := uintptr(os.Getpagesize())
	alignedPtr := ptr & ^(pageSize - 1)
	alignedLength := ((ptr + length - alignedPtr + pageSize - 1) / pageSize) * pageSize

	r1, _, _ := syscall.Syscall(syscall.SYS_MUNLOCK, alignedPtr, alignedLength, 0)
	if r1 != 0 {
		return syscall.Errno(r1)
	}

	sb.locked = false
	return nil
}

func (sb *SecureBuffer) Bytes() []byte {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	if sb.wiped {
		return nil
	}
	return sb.data
}

func (sb *SecureBuffer) Copy(src []byte) error {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	if sb.wiped {
		return errors.New("buffer has been wiped")
	}

	if len(src) > len(sb.data) {
		return errors.New("source data too large for buffer")
	}

	copy(sb.data, src)
	return nil
}

func (sb *SecureBuffer) SecureWipe() {
	sb.mutex.Lock()
	defer sb.mutex.Unlock()

	if sb.wiped {
		return
	}

	for pass := 0; pass < 3; pass++ {
		for i := range sb.data {
			sb.data[i] = byte(pass)
		}
		runtime.KeepAlive(sb.data)
	}

	for i := range sb.data {
		sb.data[i] = 0
	}
	runtime.KeepAlive(sb.data)

	sb.wiped = true
}

func (sb *SecureBuffer) Close() error {
	sb.SecureWipe()
	return sb.Unlock()
}

func SecureWipe(data []byte) {
	if data == nil {
		return
	}

	for pass := 0; pass < 3; pass++ {
		for i := range data {
			data[i] = byte(pass)
		}
		runtime.KeepAlive(data)
	}

	for i := range data {
		data[i] = 0
	}
	runtime.KeepAlive(data)
}

func SecureString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}

	strHeader := (*struct {
		data uintptr
		len  int
	})(unsafe.Pointer(s))

	if strHeader.data == 0 {
		return
	}

	data := []byte(*s)
	SecureWipe(data)

	*s = ""
}

type ProtectedKey struct {
	buffer *SecureBuffer
	keyLen int
}

func NewProtectedKey(key []byte) (*ProtectedKey, error) {
	buffer, err := NewSecureBuffer(len(key))
	if err != nil {
		return nil, err
	}

	if err := buffer.Copy(key); err != nil {
		buffer.Close()
		return nil, err
	}

	SecureWipe(key)

	return &ProtectedKey{
		buffer: buffer,
		keyLen: len(key),
	}, nil
}

func (pk *ProtectedKey) Key() []byte {
	if pk.buffer == nil {
		return nil
	}

	data := pk.buffer.Bytes()
	if data == nil {
		return nil
	}

	keyCopy := make([]byte, pk.keyLen)
	copy(keyCopy, data[:pk.keyLen])
	return keyCopy
}

func (pk *ProtectedKey) Close() error {
	if pk.buffer != nil {
		return pk.buffer.Close()
	}
	return nil
}

type XChaChaWrapper struct {
	aead cipher.AEAD
}

func NewXChaChaWrapper(key []byte) (*XChaChaWrapper, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &XChaChaWrapper{aead: aead}, nil
}

func (w *XChaChaWrapper) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, w.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := w.aead.Seal(nonce, nonce, plaintext, nil)

	SecureWipe(plaintext)

	return ciphertext, nil
}

func (w *XChaChaWrapper) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := w.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := w.aead.Open(nil, nonce, sealed, nil)

	return plaintext, err
}

func GenerateFingerprint(onionAddress string) string {
	hash := sha256.Sum256([]byte(onionAddress))
	seed := binary.BigEndian.Uint64(hash[:8])
	r := mRand.New(mRand.NewSource(int64(seed)))

	var words []string
	for range 5 {
		word1 := adverbs[r.Intn(len(adverbs))]
		word2 := adjectives[r.Intn(len(adjectives))]
		word3 := animals[r.Intn(len(animals))]
		group := fmt.Sprintf("%s-%s-%s", word1, word2, word3)
		words = append(words, group)
	}
	return strings.Join(words, " ")
}

// ============================================================================
// TRAFFIC SHAPING AND PADDING SECTION
// ============================================================================

type TrafficShaper struct {
	config      *PaddingConfig
	recentSizes []int
	avgSize     int
	mutex       sync.RWMutex
	lastSend    time.Time
	sendMutex   sync.Mutex
}

func NewTrafficShaper(config *PaddingConfig) *TrafficShaper {
	return &TrafficShaper{
		config:      config,
		recentSizes: make([]int, 0, 100),
		avgSize:     config.DefaultSize,
	}
}

func (ts *TrafficShaper) calculateDynamicPadding(messageSize int) int {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	if !ts.config.DynamicPadding {
		return ts.config.MinSize
	}

	ts.recentSizes = append(ts.recentSizes, messageSize)
	if len(ts.recentSizes) > 50 {
		ts.recentSizes = ts.recentSizes[1:]
	}

	if len(ts.recentSizes) > 5 {
		sum := 0
		for _, size := range ts.recentSizes {
			sum += size
		}
		ts.avgSize = sum / len(ts.recentSizes)
	}

	targetSize := ts.avgSize
	if ts.config.AdaptiveSize {
		variance := 0.0
		for _, size := range ts.recentSizes {
			diff := float64(size - ts.avgSize)
			variance += diff * diff
		}
		if len(ts.recentSizes) > 1 {
			variance /= float64(len(ts.recentSizes) - 1)
		}
		stdDev := math.Sqrt(variance)
		targetSize = int(float64(ts.avgSize) + stdDev*0.5)
	}

	if targetSize < ts.config.MinSize {
		targetSize = ts.config.MinSize
	}
	if targetSize > ts.config.MaxSize {
		targetSize = ts.config.MaxSize
	}

	paddingNeeded := targetSize - messageSize
	if paddingNeeded < 0 {
		paddingNeeded = ts.config.MinSize
	}

	return paddingNeeded
}

func (ts *TrafficShaper) generateJitter(jitterRangeMs int) time.Duration {
	if !ts.config.JitterEnabled {
		return 0
	}

	jitterMs := mRand.Intn(jitterRangeMs*2) - jitterRangeMs
	if jitterMs < 0 {
		jitterMs = 0
	}

	return time.Duration(jitterMs) * time.Millisecond
}

func (ts *TrafficShaper) applyTimingObfuscation(jitterRangeMs int) {
	ts.sendMutex.Lock()
	defer ts.sendMutex.Unlock()

	now := time.Now()
	minInterval := 50 * time.Millisecond
	timeSinceLastSend := now.Sub(ts.lastSend)

	if timeSinceLastSend < minInterval {
		sleepTime := minInterval - timeSinceLastSend
		time.Sleep(sleepTime)
	}

	jitter := ts.generateJitter(jitterRangeMs)
	if jitter > 0 {
		time.Sleep(jitter)
	}

	ts.lastSend = time.Now()
}

func (ts *TrafficShaper) padMessage(env *Envelope) {
	var buf bytes.Buffer
	gob.NewEncoder(&buf).Encode(env)
	currentSize := buf.Len()

	paddingSize := ts.calculateDynamicPadding(currentSize)
	if paddingSize > 0 {
		padding := make([]byte, paddingSize)
		rand.Read(padding)
		env.Padding = padding
	}
}

type DummyTrafficGenerator struct {
	messenger *Messenger
	active    bool
	stopCh    chan struct{}
	mutex     sync.RWMutex
}

func NewDummyTrafficGenerator(messenger *Messenger) *DummyTrafficGenerator {
	return &DummyTrafficGenerator{
		messenger: messenger,
		stopCh:    make(chan struct{}),
	}
}

func (dtg *DummyTrafficGenerator) Start() {
	dtg.mutex.Lock()
	defer dtg.mutex.Unlock()

	if dtg.active {
		return
	}

	dtg.active = true
	go dtg.generateDummyTraffic()
}

func (dtg *DummyTrafficGenerator) Stop() {
	dtg.mutex.Lock()
	defer dtg.mutex.Unlock()

	if !dtg.active {
		return
	}

	dtg.active = false
	close(dtg.stopCh)
}

func (dtg *DummyTrafficGenerator) generateDummyTraffic() {
	ticker := time.NewTicker(dtg.messenger.config.Network.DummyTrafficInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dtg.sendDummyPackets()
		case <-dtg.stopCh:
			return
		}
	}
}

func (dtg *DummyTrafficGenerator) sendDummyPackets() {
	dtg.messenger.mutex.RLock()
	peers := make([]*SecureChannel, 0, len(dtg.messenger.peers))
	for _, peer := range dtg.messenger.peers {
		peers = append(peers, peer)
	}
	dtg.messenger.mutex.RUnlock()

	if len(peers) == 0 {
		return
	}

	numPackets := mRand.Intn(dtg.messenger.config.Network.MaxDummyPackets) + 1
	for i := 0; i < numPackets; i++ {
		if len(peers) > 0 {
			peer := peers[mRand.Intn(len(peers))]
			go dtg.sendDummyPacket(peer)
		}
		time.Sleep(time.Duration(mRand.Intn(1000)) * time.Millisecond)
	}
}

func (dtg *DummyTrafficGenerator) sendDummyPacket(peer *SecureChannel) {
	dummyData := make([]byte, mRand.Intn(512)+256)
	rand.Read(dummyData)

	env := Envelope{
		Type:      TypeDummyTraffic,
		Data:      dummyData,
		Timestamp: time.Now().Unix(),
	}
	peer.Send(&env)
	SecureWipe(dummyData)
}

// ============================================================================
// MESSAGE TYPES AND STRUCTURES SECTION
// ============================================================================

type MessageType string

const (
	TypeKyberPub         MessageType = "KYBER_PUB"
	TypeKyberCT          MessageType = "KYBER_CT"
	TypePeerID           MessageType = "PEER_ID"
	TypeChatMsg          MessageType = "CHAT_MSG"
	TypeHeartbeat        MessageType = "HEARTBEAT"
	TypeHeartbeatAck     MessageType = "HEARTBEAT_ACK"
	TypeApprovalRequest  MessageType = "APPROVAL_REQUEST"
	TypeApprovalResponse MessageType = "APPROVAL_RESPONSE"
	TypeKeyRotationReq   MessageType = "KEY_ROTATION_REQ"
	TypeKeyRotationResp  MessageType = "KEY_ROTATION_RESP"
	TypeDummyTraffic     MessageType = "DUMMY_TRAFFIC"
)

type Envelope struct {
	Type      MessageType `json:"type"`
	Data      []byte      `json:"data"`
	HMAC      []byte      `json:"hmac"`
	SeqNum    uint64      `json:"seq_num"`
	Timestamp int64       `json:"timestamp"`
	Padding   []byte      `json:"padding,omitempty"`
}

type ChatMessage struct {
	From    string `json:"from"`
	Content string `json:"content"`
	Time    int64  `json:"time"`
}

type KeyRotationRequest struct {
	NewPublicKey []byte `json:"new_public_key"`
	Timestamp    int64  `json:"timestamp"`
	Nonce        []byte `json:"nonce"`
}

type KeyRotationResponse struct {
	NewPublicKey []byte `json:"new_public_key"`
	Timestamp    int64  `json:"timestamp"`
	Nonce        []byte `json:"nonce"`
}

type Friend struct {
	OnionAddress string `json:"onion_address"`
	Nickname     string `json:"nickname"`
	Approved     bool   `json:"approved"`
	LastSeen     int64  `json:"last_seen"`
}

// ============================================================================
// KEY MANAGEMENT SECTION
// ============================================================================

type EphemeralKeyPair struct {
	PublicKey    []byte        `json:"public_key"`
	privateKey   *ProtectedKey `json:"-"`
	CreatedAt    time.Time     `json:"created_at"`
	MessageCount int           `json:"message_count"`
	LastRotation time.Time     `json:"last_rotation"`
}

func NewEphemeralKeyPairFromBytes(pubKey, privKey []byte) (*EphemeralKeyPair, error) {
	protectedPrivKey, err := NewProtectedKey(privKey)
	if err != nil {
		return nil, err
	}
	return &EphemeralKeyPair{
		PublicKey:    pubKey,
		privateKey:   protectedPrivKey,
		CreatedAt:    time.Now(),
		MessageCount: 0,
		LastRotation: time.Now(),
	}, nil
}

func (ekp *EphemeralKeyPair) PrivateKey() []byte {
	if ekp.privateKey == nil {
		return nil
	}
	return ekp.privateKey.Key()
}

func (ekp *EphemeralKeyPair) Close() error {
	SecureWipe(ekp.PublicKey)
	if ekp.privateKey != nil {
		return ekp.privateKey.Close()
	}
	return nil
}

type EphemeralKeyManager struct {
	keys   map[string]*EphemeralKeyPair
	mutex  sync.RWMutex
	config *SecurityConfig
}

func NewEphemeralKeyManager(config *SecurityConfig) *EphemeralKeyManager {
	return &EphemeralKeyManager{
		keys:   make(map[string]*EphemeralKeyPair),
		config: config,
	}
}

func (ekm *EphemeralKeyManager) GenerateKeyPair() (*EphemeralKeyPair, error) {
	kem := kyber1024.Scheme()
	pubKey, privKey, err := kem.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	pubKeyData, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	privKeyData, err := privKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	keyPair, err := NewEphemeralKeyPairFromBytes(pubKeyData, privKeyData)
	if err != nil {
		SecureWipe(pubKeyData)
		SecureWipe(privKeyData)
		return nil, err
	}

	return keyPair, nil
}

func (ekm *EphemeralKeyManager) GetOrCreateKeyPair(peerOnion string) (*EphemeralKeyPair, error) {
	ekm.mutex.Lock()
	defer ekm.mutex.Unlock()

	if keyPair, exists := ekm.keys[peerOnion]; exists {
		return keyPair, nil
	}

	keyPair, err := ekm.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	ekm.keys[peerOnion] = keyPair
	return keyPair, nil
}

func (ekm *EphemeralKeyManager) RotateKey(peerOnion string) (*EphemeralKeyPair, error) {
	ekm.mutex.Lock()
	defer ekm.mutex.Unlock()

	if oldKeyPair, exists := ekm.keys[peerOnion]; exists {
		oldKeyPair.Close()
	}

	keyPair, err := ekm.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	ekm.keys[peerOnion] = keyPair
	return keyPair, nil
}

func (ekm *EphemeralKeyManager) ShouldRotateKey(peerOnion string) bool {
	ekm.mutex.RLock()
	defer ekm.mutex.RUnlock()

	keyPair, exists := ekm.keys[peerOnion]
	if !exists {
		return false
	}

	timeSinceRotation := time.Since(keyPair.LastRotation)
	return timeSinceRotation > ekm.config.KeyRotationInterval || keyPair.MessageCount >= ekm.config.MaxMessagesBeforeRotation
}

func (ekm *EphemeralKeyManager) IncrementMessageCount(peerOnion string) {
	ekm.mutex.Lock()
	defer ekm.mutex.Unlock()

	if keyPair, exists := ekm.keys[peerOnion]; exists {
		keyPair.MessageCount++
	}
}

func (ekm *EphemeralKeyManager) Close() {
	ekm.mutex.Lock()
	defer ekm.mutex.Unlock()

	for _, keyPair := range ekm.keys {
		keyPair.Close()
	}
	ekm.keys = make(map[string]*EphemeralKeyPair)
}

// ============================================================================
// SESSION MANAGEMENT SECTION
// ============================================================================

type PeerSession struct {
	PeerOnion          string
	CurrentKeyPair     *EphemeralKeyPair
	PeerPublicKey      []byte
	hmacKey            *ProtectedKey
	OutgoingSeqNum     uint64
	IncomingSeqNum     uint64
	ReceivedSeqNums    map[uint64]bool
	LastActivity       time.Time
	encryptionKey      *ProtectedKey
	authenticationKey  *ProtectedKey
	KeyRotationPending bool
	PendingKeyPair     *EphemeralKeyPair
	trafficShaper      *TrafficShaper
}

func (ps *PeerSession) SetEncryptionKey(key []byte) error {
	if ps.encryptionKey != nil {
		ps.encryptionKey.Close()
	}

	protectedKey, err := NewProtectedKey(key)
	if err != nil {
		return err
	}

	ps.encryptionKey = protectedKey
	return nil
}

func (ps *PeerSession) GetEncryptionKey() []byte {
	if ps.encryptionKey == nil {
		return nil
	}
	return ps.encryptionKey.Key()
}

func (ps *PeerSession) SetAuthenticationKey(key []byte) error {
	if ps.authenticationKey != nil {
		ps.authenticationKey.Close()
	}

	protectedKey, err := NewProtectedKey(key)
	if err != nil {
		return err
	}

	ps.authenticationKey = protectedKey
	return nil
}

func (ps *PeerSession) GetAuthenticationKey() []byte {
	if ps.authenticationKey == nil {
		return nil
	}
	return ps.authenticationKey.Key()
}

func (ps *PeerSession) GenerateHMAC(message []byte) []byte {
	authKey := ps.GetAuthenticationKey()
	if authKey == nil {
		return nil
	}
	defer SecureWipe(authKey)

	h := hmac.New(sha256.New, authKey)
	h.Write(message)
	return h.Sum(nil)
}

func (ps *PeerSession) VerifyHMAC(message, expectedMAC []byte) bool {
	authKey := ps.GetAuthenticationKey()
	if authKey == nil {
		return false
	}
	defer SecureWipe(authKey)

	h := hmac.New(sha256.New, authKey)
	h.Write(message)
	computedMAC := h.Sum(nil)
	defer SecureWipe(computedMAC)

	return hmac.Equal(computedMAC, expectedMAC)
}

func (ps *PeerSession) Close() error {
	SecureWipe(ps.PeerPublicKey)

	if ps.CurrentKeyPair != nil {
		ps.CurrentKeyPair.Close()
	}

	if ps.PendingKeyPair != nil {
		ps.PendingKeyPair.Close()
	}

	if ps.hmacKey != nil {
		ps.hmacKey.Close()
	}

	if ps.encryptionKey != nil {
		ps.encryptionKey.Close()
	}

	if ps.authenticationKey != nil {
		ps.authenticationKey.Close()
	}

	return nil
}

func (ps *PeerSession) GetNextSequenceNumber() uint64 {
	ps.OutgoingSeqNum++
	return ps.OutgoingSeqNum
}

func (ps *PeerSession) ValidateSequenceNumber(seqNum uint64, sequenceWindowSize int) bool {
	if seqNum <= ps.IncomingSeqNum {
		if _, exists := ps.ReceivedSeqNums[seqNum]; exists {
			return false
		}
	}

	if seqNum > ps.IncomingSeqNum {
		for seq := ps.IncomingSeqNum + 1; seq < seqNum; seq++ {
			ps.ReceivedSeqNums[seq] = false
		}
		ps.IncomingSeqNum = seqNum
	}

	ps.ReceivedSeqNums[seqNum] = true

	if len(ps.ReceivedSeqNums) > sequenceWindowSize {
		oldestSeq := ps.IncomingSeqNum - uint64(sequenceWindowSize)
		for seq := range ps.ReceivedSeqNums {
			if seq < oldestSeq {
				delete(ps.ReceivedSeqNums, seq)
			}
		}
	}

	return true
}

type SessionManager struct {
	sessions map[string]*PeerSession
	mutex    sync.RWMutex
	config   *SecurityConfig
}

func NewSessionManager(config *SecurityConfig) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*PeerSession),
		config:   config,
	}
}

func (sm *SessionManager) GetOrCreateSession(peerOnion string) *PeerSession {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if session, exists := sm.sessions[peerOnion]; exists {
		return session
	}

	session := &PeerSession{
		PeerOnion:       peerOnion,
		OutgoingSeqNum:  0,
		IncomingSeqNum:  0,
		ReceivedSeqNums: make(map[uint64]bool),
		LastActivity:    time.Now(),
	}
	sm.sessions[peerOnion] = session
	return session
}

func (sm *SessionManager) UpdateSessionKeys(peerOnion string, encKey, authKey []byte, paddingConfig *PaddingConfig) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if session, exists := sm.sessions[peerOnion]; exists {
		session.SetEncryptionKey(encKey)
		session.SetAuthenticationKey(authKey)
		session.LastActivity = time.Now()
		session.trafficShaper = NewTrafficShaper(paddingConfig)

		SecureWipe(encKey)
		SecureWipe(authKey)
	}
}

func (sm *SessionManager) Close() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	for _, session := range sm.sessions {
		session.Close()
	}
	sm.sessions = make(map[string]*PeerSession)
}

// ============================================================================
// NETWORK TRANSPORT SECTION
// ============================================================================

type SecureChannel struct {
	conn    net.Conn
	cipher  *XChaChaWrapper
	session *PeerSession
	mutex   sync.Mutex
	config  *Config
}

func (sc *SecureChannel) Send(env *Envelope) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if sc.session != nil {
		env.SeqNum = sc.session.GetNextSequenceNumber()

		if sc.session.trafficShaper != nil {
			sc.session.trafficShaper.padMessage(env)
			sc.session.trafficShaper.applyTimingObfuscation(sc.config.Network.JitterRangeMs)
		}
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(env); err != nil {
		return err
	}

	messageData := buf.Bytes()

	if sc.session != nil {
		authKey := sc.session.GetAuthenticationKey()
		if authKey != nil {
			env.HMAC = sc.session.GenerateHMAC(messageData)
			buf.Reset()
			if err := gob.NewEncoder(&buf).Encode(env); err != nil {
				SecureWipe(authKey)
				return err
			}
			messageData = buf.Bytes()
		}
		SecureWipe(authKey)
	}

	encrypted, err := sc.cipher.Encrypt(messageData)
	if err != nil {
		SecureWipe(messageData)
		return err
	}

	err = gob.NewEncoder(sc.conn).Encode(encrypted)

	SecureWipe(messageData)
	SecureWipe(encrypted)

	return err
}

func (sc *SecureChannel) Receive(env *Envelope) error {
	var encrypted []byte
	if err := gob.NewDecoder(sc.conn).Decode(&encrypted); err != nil {
		return err
	}
	defer SecureWipe(encrypted)

	decrypted, err := sc.cipher.Decrypt(encrypted)
	if err != nil {
		return err
	}
	defer SecureWipe(decrypted)

	if err := gob.NewDecoder(bytes.NewReader(decrypted)).Decode(env); err != nil {
		return err
	}

	if sc.session != nil && len(env.HMAC) > 0 {
		authKey := sc.session.GetAuthenticationKey()
		if authKey != nil {
			originalHMAC := make([]byte, len(env.HMAC))
			copy(originalHMAC, env.HMAC)
			env.HMAC = nil

			var buf bytes.Buffer
			if err := gob.NewEncoder(&buf).Encode(env); err != nil {
				SecureWipe(authKey)
				SecureWipe(originalHMAC)
				return err
			}

			if !sc.session.VerifyHMAC(buf.Bytes(), originalHMAC) {
				SecureWipe(authKey)
				SecureWipe(originalHMAC)
				SecureWipe(buf.Bytes())
				return errors.New("HMAC verification failed")
			}

			if !sc.session.ValidateSequenceNumber(env.SeqNum, sc.config.Security.SequenceWindowSize) {
				SecureWipe(authKey)
				SecureWipe(originalHMAC)
				SecureWipe(buf.Bytes())
				return errors.New("invalid sequence number - possible replay attack")
			}

			env.HMAC = originalHMAC
			SecureWipe(authKey)
			SecureWipe(buf.Bytes())
		}
	}

	return nil
}

// ============================================================================
// CORE MESSENGER SECTION
// ============================================================================

type MessengerCallbacks struct {
	OnMessageReceived   func(ChatMessage)
	OnStatusUpdate      func(string)
	OnFriendUpdate      func()
	OnPeerConnected     func(string)
	OnPeerDisconnected  func(string)
	OnApprovalRequested func(string)
	OnKeyRotated        func(string)
}

type Messenger struct {
	id                    string
	onion                 string
	tor                   *tor.Tor
	listener              net.Listener
	peers                 map[string]*SecureChannel
	friends               map[string]*Friend
	friendsFilePath       string
	mutex                 sync.RWMutex
	ctx                   context.Context
	cancel                context.CancelFunc
	callbacks             *MessengerCallbacks
	ready                 bool
	readyMutex            sync.RWMutex
	keyManager            *EphemeralKeyManager
	sessionManager        *SessionManager
	dummyTrafficGenerator *DummyTrafficGenerator
	circuitRotationMutex  sync.Mutex
	config                *Config
}

func NewMessenger(config *Config) (*Messenger, error) {
	ctx, cancel := context.WithCancel(context.Background())

	configDir := filepath.Join(config.Files.ConfigDir, config.User)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		cancel()
		return nil, fmt.Errorf("could not create config directory: %w", err)
	}

	m := &Messenger{
		id:              config.User,
		peers:           make(map[string]*SecureChannel),
		friends:         make(map[string]*Friend),
		friendsFilePath: filepath.Join(configDir, config.Files.FriendsFilename),
		ctx:             ctx,
		cancel:          cancel,
		callbacks:       &MessengerCallbacks{},
		keyManager:      NewEphemeralKeyManager(&config.Security),
		sessionManager:  NewSessionManager(&config.Security),
		config:          config,
	}

	m.dummyTrafficGenerator = NewDummyTrafficGenerator(m)

	if err := m.loadFriends(); err != nil {
		log.Printf("Could not load friends file: %v", err)
	}

	if err := m.setupTor(); err != nil {
		cancel()
		return nil, err
	}

	return m, nil
}

func (m *Messenger) setupTor() error {
	log.Println("🔄 Starting Tor...")
	var debugWriter io.Writer = io.Discard
	if m.config.Verbose {
		debugWriter = os.Stdout
	}

	torDataDir := m.config.Tor.DataDir
	if torDataDir == "" {
		torDataDir = filepath.Join(m.config.Files.ConfigDir, m.config.User, "tor")
	}

	t, err := tor.Start(m.ctx, &tor.StartConf{
		DataDir:     torDataDir,
		DebugWriter: debugWriter,
	})
	if err != nil {
		return fmt.Errorf("tor start failed: %w", err)
	}
	m.tor = t

	log.Println("⏳ Bootstrapping Tor network...")
	if err := t.EnableNetwork(m.ctx, true); err != nil {
		return fmt.Errorf("tor network enable failed: %w", err)
	}

	log.Println("🧅 Creating onion service...")
	onion, err := t.Listen(m.ctx, &tor.ListenConf{
		RemotePorts: []int{m.config.Tor.Port},
		Version3:    true,
	})
	if err != nil {
		return fmt.Errorf("hidden service creation failed: %w", err)
	}
	m.listener = onion
	m.onion = fmt.Sprintf("%s.onion", onion.ID)
	m.readyMutex.Lock()
	m.ready = true
	m.readyMutex.Unlock()
	log.Println("✅ Tor is ready!")
	return nil
}

func (m *Messenger) startKeyRotationScheduler() {
	ticker := time.NewTicker(m.config.Security.KeyRotationInterval / 4)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkAndRotateKeys()
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *Messenger) startCircuitRotation(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.circuitRotationMutex.Lock()
			ctrl := m.tor.Control
			if ctrl == nil {
				log.Printf("Error: Tor control connection is not available")
			} else {
				defer ctrl.Close()
				_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := ctrl.Signal("NEWNYM"); err != nil {
					log.Printf("Error sending NEWNYM signal: %v", err)
				} else {
					log.Println("🔄 Tor circuit rotated successfully.")
				}
			}
			m.circuitRotationMutex.Unlock()
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *Messenger) checkAndRotateKeys() {
	m.mutex.RLock()
	peers := make([]string, 0, len(m.peers))
	for peerOnion := range m.peers {
		peers = append(peers, peerOnion)
	}
	m.mutex.RUnlock()

	for _, peerOnion := range peers {
		if m.keyManager.ShouldRotateKey(peerOnion) {
			go m.initiateKeyRotation(peerOnion)
		}
	}
}

func (m *Messenger) initiateKeyRotation(peerOnion string) error {
	m.mutex.RLock()
	peer, exists := m.peers[peerOnion]
	friend, friendExists := m.friends[peerOnion]
	m.mutex.RUnlock()

	if !exists || !friendExists {
		return fmt.Errorf("peer or friend not found")
	}

	newKeyPair, err := m.keyManager.RotateKey(peerOnion)
	if err != nil {
		return fmt.Errorf("failed to rotate key: %w", err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	defer SecureWipe(nonce)

	rotationReq := KeyRotationRequest{
		NewPublicKey: newKeyPair.PublicKey,
		Timestamp:    time.Now().Unix(),
		Nonce:        nonce,
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&rotationReq); err != nil {
		return err
	}

	env := Envelope{
		Type:      TypeKeyRotationReq,
		Data:      buf.Bytes(),
		Timestamp: time.Now().Unix(),
	}

	if err := peer.Send(&env); err != nil {
		return fmt.Errorf("failed to send key rotation request: %w", err)
	}

	if m.callbacks.OnKeyRotated != nil {
		m.callbacks.OnKeyRotated(friend.Nickname)
	}

	return nil
}

func (m *Messenger) handleKeyRotationRequest(peerOnion string, data []byte, secureConn *SecureChannel) error {
	var rotationReq KeyRotationRequest
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&rotationReq); err != nil {
		return err
	}

	newKeyPair, err := m.keyManager.RotateKey(peerOnion)
	if err != nil {
		return err
	}

	privKey := newKeyPair.PrivateKey()
	defer SecureWipe(privKey)

	if err := m.performKeyExchange(peerOnion, privKey, rotationReq.NewPublicKey, secureConn); err != nil {
		return err
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	defer SecureWipe(nonce)

	rotationResp := KeyRotationResponse{
		NewPublicKey: newKeyPair.PublicKey,
		Timestamp:    time.Now().Unix(),
		Nonce:        nonce,
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&rotationResp); err != nil {
		return err
	}

	env := Envelope{
		Type:      TypeKeyRotationResp,
		Data:      buf.Bytes(),
		Timestamp: time.Now().Unix(),
	}

	return secureConn.Send(&env)
}

func (m *Messenger) handleKeyRotationResponse(peerOnion string, data []byte, secureConn *SecureChannel) error {
	var rotationResp KeyRotationResponse
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&rotationResp); err != nil {
		return err
	}

	keyPair, err := m.keyManager.GetOrCreateKeyPair(peerOnion)
	if err != nil {
		return err
	}

	privKey := keyPair.PrivateKey()
	defer SecureWipe(privKey)

	return m.performKeyExchange(peerOnion, privKey, rotationResp.NewPublicKey, secureConn)
}

func (m *Messenger) performKeyExchange(peerOnion string, privateKey, peerPublicKey []byte, secureConn *SecureChannel) error {
	kem := kyber1024.Scheme()

	pubKey, err := kem.UnmarshalBinaryPublicKey(peerPublicKey)
	if err != nil {
		return err
	}

	ciphertext, sharedSecret, err := kem.Encapsulate(pubKey)
	if err != nil {
		return err
	}
	defer SecureWipe(sharedSecret)

	encKey, authKey, err := m.deriveSessionKeys(sharedSecret)
	if err != nil {
		return err
	}
	defer SecureWipe(encKey)
	defer SecureWipe(authKey)

	cipher, err := NewXChaChaWrapper(encKey)
	if err != nil {
		return err
	}

	secureConn.mutex.Lock()
	secureConn.cipher = cipher
	secureConn.config = m.config
	if secureConn.session == nil {
		secureConn.session = m.sessionManager.GetOrCreateSession(peerOnion)
	}
	SecureWipe(secureConn.session.PeerPublicKey)
	secureConn.session.PeerPublicKey = make([]byte, len(peerPublicKey))
	copy(secureConn.session.PeerPublicKey, peerPublicKey)
	secureConn.session.LastActivity = time.Now()
	secureConn.mutex.Unlock()

	m.sessionManager.UpdateSessionKeys(peerOnion, encKey, authKey, &m.config.Padding)

	SecureWipe(ciphertext)

	return nil
}

func (m *Messenger) deriveSessionKeys(sharedSecret []byte) ([]byte, []byte, error) {
	hkdf := hkdf.New(sha256.New, sharedSecret, nil, []byte(ProtocolInfo))

	encKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf, encKey); err != nil {
		return nil, nil, err
	}

	authKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, authKey); err != nil {
		SecureWipe(encKey)
		return nil, nil, err
	}

	return encKey, authKey, nil
}

func (m *Messenger) managePeer(peerOnion string, secureConn *SecureChannel) {
	defer m.removePeer(peerOnion)
	heartbeatTicker := time.NewTicker(m.config.Network.HeartbeatInterval)
	defer heartbeatTicker.Stop()

	go func() {
		for {
			select {
			case <-heartbeatTicker.C:
				heartbeatEnv := Envelope{
					Type:      TypeHeartbeat,
					Timestamp: time.Now().Unix(),
				}
				if err := secureConn.Send(&heartbeatEnv); err != nil {
					return
				}
			case <-m.ctx.Done():
				return
			}
		}
	}()

	for {
		secureConn.conn.SetReadDeadline(time.Now().Add(m.config.Network.HeartbeatTimeout))
		var env Envelope
		err := secureConn.Receive(&env)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("Connection to %s timed out.", peerOnion[:16]+"...")
			}
			return
		}

		m.updateLastSeen(peerOnion)
		switch env.Type {
		case TypeChatMsg:
			var msg ChatMessage
			if err := gob.NewDecoder(bytes.NewReader(env.Data)).Decode(&msg); err != nil {
				continue
			}
			if m.callbacks.OnMessageReceived != nil {
				m.callbacks.OnMessageReceived(msg)
			}
			m.keyManager.IncrementMessageCount(peerOnion)
		case TypeHeartbeat:
			ackEnv := Envelope{
				Type:      TypeHeartbeatAck,
				Timestamp: time.Now().Unix(),
			}
			secureConn.Send(&ackEnv)
		case TypeHeartbeatAck:
		case TypeApprovalRequest:
			m.mutex.RLock()
			friend, ok := m.friends[peerOnion]
			m.mutex.RUnlock()
			if ok && m.callbacks.OnApprovalRequested != nil {
				m.callbacks.OnApprovalRequested(friend.Nickname)
			}
		case TypeKeyRotationReq:
			go m.handleKeyRotationRequest(peerOnion, env.Data, secureConn)
		case TypeKeyRotationResp:
			go m.handleKeyRotationResponse(peerOnion, env.Data, secureConn)
		case TypeDummyTraffic:
		}

		SecureWipe(env.Data)
		SecureWipe(env.HMAC)
		SecureWipe(env.Padding)
	}
}

func (m *Messenger) acceptConnections() {
	log.Printf("👂 Listening for connections on %s", m.onion)
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			if errors.Is(m.ctx.Err(), context.Canceled) {
				return
			}
			continue
		}
		go m.handleIncomingConnection(conn)
	}
}

func (m *Messenger) handleIncomingConnection(conn net.Conn) {
	defer conn.Close()
	peerOnion, secureConn, err := m.performServerHandshake(conn)
	if err != nil {
		return
	}
	m.mutex.RLock()
	friend, ok := m.friends[peerOnion]
	m.mutex.RUnlock()
	if !ok {
		return
	}
	if !friend.Approved {
		if m.callbacks.OnApprovalRequested != nil {
			m.callbacks.OnApprovalRequested(friend.Nickname)
		}
		return
	}
	m.addPeer(peerOnion, secureConn)
	m.managePeer(peerOnion, secureConn)
}

func (m *Messenger) performServerHandshake(conn net.Conn) (string, *SecureChannel, error) {
	conn.SetDeadline(time.Now().Add(m.config.Tor.HSTimeout))
	defer conn.SetDeadline(time.Time{})
	var clientPubKey Envelope
	if err := gob.NewDecoder(conn).Decode(&clientPubKey); err != nil {
		return "", nil, err
	}
	defer SecureWipe(clientPubKey.Data)

	kem := kyber1024.Scheme()
	pubKey, err := kem.UnmarshalBinaryPublicKey(clientPubKey.Data)
	if err != nil {
		return "", nil, err
	}
	ciphertext, sharedSecret, err := kem.Encapsulate(pubKey)
	if err != nil {
		return "", nil, err
	}
	defer SecureWipe(sharedSecret)

	ctEnvelope := Envelope{Type: TypeKyberCT, Data: ciphertext}
	if err := gob.NewEncoder(conn).Encode(&ctEnvelope); err != nil {
		return "", nil, err
	}

	encKey, authKey, err := m.deriveSessionKeys(sharedSecret)
	if err != nil {
		return "", nil, err
	}

	cipher, err := NewXChaChaWrapper(encKey)
	if err != nil {
		SecureWipe(encKey)
		SecureWipe(authKey)
		return "", nil, err
	}

	secureConn := &SecureChannel{
		conn:   conn,
		cipher: cipher,
		config: m.config,
	}

	var onionEnv Envelope
	if err := secureConn.Receive(&onionEnv); err != nil {
		return "", nil, err
	}
	peerOnion := string(onionEnv.Data)
	SecureWipe(onionEnv.Data)

	session := m.sessionManager.GetOrCreateSession(peerOnion)
	session.SetEncryptionKey(encKey)
	session.SetAuthenticationKey(authKey)
	session.trafficShaper = NewTrafficShaper(&m.config.Padding)
	secureConn.session = session

	myIdEnv := Envelope{Type: TypePeerID, Data: []byte(m.onion)}
	if err := secureConn.Send(&myIdEnv); err != nil {
		return "", nil, err
	}
	return peerOnion, secureConn, nil
}

func (m *Messenger) performClientHandshake(conn net.Conn) (*SecureChannel, error) {
	conn.SetDeadline(time.Now().Add(m.config.Tor.HSTimeout))
	defer conn.SetDeadline(time.Time{})
	kem := kyber1024.Scheme()
	pubKey, privKey, err := kem.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	pubKeyData, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	privKeyData, err := privKey.MarshalBinary()
	if err != nil {
		SecureWipe(pubKeyData)
		return nil, err
	}
	defer SecureWipe(privKeyData)

	pubKeyEnv := Envelope{Type: TypeKyberPub, Data: pubKeyData}
	if err := gob.NewEncoder(conn).Encode(&pubKeyEnv); err != nil {
		return nil, err
	}
	var ctEnvelope Envelope
	if err := gob.NewDecoder(conn).Decode(&ctEnvelope); err != nil {
		return nil, err
	}

	sharedSecret, err := kem.Decapsulate(privKey, ctEnvelope.Data)
	if err != nil {
		return nil, err
	}
	defer SecureWipe(sharedSecret)

	encKey, authKey, err := m.deriveSessionKeys(sharedSecret)
	if err != nil {
		return nil, err
	}

	cipher, err := NewXChaChaWrapper(encKey)
	if err != nil {
		SecureWipe(encKey)
		SecureWipe(authKey)
		return nil, err
	}

	secureConn := &SecureChannel{
		conn:   conn,
		cipher: cipher,
		config: m.config,
	}

	myIdEnv := Envelope{Type: TypePeerID, Data: []byte(m.onion)}
	if err := secureConn.Send(&myIdEnv); err != nil {
		return nil, err
	}
	var peerIdEnv Envelope
	if err := secureConn.Receive(&peerIdEnv); err != nil {
		return nil, err
	}

	peerOnion := string(peerIdEnv.Data)
	SecureWipe(peerIdEnv.Data)

	session := m.sessionManager.GetOrCreateSession(peerOnion)
	session.SetEncryptionKey(encKey)
	session.SetAuthenticationKey(authKey)
	session.trafficShaper = NewTrafficShaper(&m.config.Padding)
	secureConn.session = session

	return secureConn, nil
}

// ============================================================================
// FRIEND MANAGEMENT SECTION
// ============================================================================

func (m *Messenger) AddFriend(onion, nickname string) error {
	if !strings.HasSuffix(onion, ".onion") || len(onion) < 60 {
		return errors.New("invalid onion address format")
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()
	if _, exists := m.friends[onion]; exists {
		return errors.New("friend with this onion address already exists")
	}
	for _, f := range m.friends {
		if f.Nickname == nickname {
			return fmt.Errorf("friend with nickname '%s' already exists", nickname)
		}
	}
	m.friends[onion] = &Friend{OnionAddress: onion, Nickname: nickname}
	if err := m.saveFriends(); err != nil {
		delete(m.friends, onion)
		return err
	}
	if m.callbacks.OnFriendUpdate != nil {
		m.callbacks.OnFriendUpdate()
	}

	fmt.Printf("\n✅ Friend '%s' added. Use `/fingerprint %s` to verify their identity.\n", nickname, nickname)
	return nil
}

func (m *Messenger) ApproveFriend(nickname string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	var targetFriend *Friend
	for _, f := range m.friends {
		if f.Nickname == nickname {
			targetFriend = f
			break
		}
	}
	if targetFriend == nil {
		return fmt.Errorf("friend '%s' not found", nickname)
	}
	targetFriend.Approved = true
	if err := m.saveFriends(); err != nil {
		targetFriend.Approved = false
		return err
	}
	if m.callbacks.OnFriendUpdate != nil {
		m.callbacks.OnFriendUpdate()
	}
	go m.connectToFriend(nickname)
	return nil
}

func (m *Messenger) RemoveFriend(nickname string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	var onionToRemove string
	for onion, f := range m.friends {
		if f.Nickname == nickname {
			onionToRemove = onion
			break
		}
	}
	if onionToRemove == "" {
		return fmt.Errorf("friend '%s' not found", nickname)
	}
	if peer, ok := m.peers[onionToRemove]; ok {
		peer.conn.Close()
	}
	delete(m.friends, onionToRemove)
	if err := m.saveFriends(); err != nil {
		return err
	}
	if m.callbacks.OnFriendUpdate != nil {
		m.callbacks.OnFriendUpdate()
	}
	return nil
}

func (m *Messenger) connectToFriend(nickname string) (*SecureChannel, error) {
	m.mutex.RLock()
	var targetFriend *Friend
	for _, f := range m.friends {
		if f.Nickname == nickname {
			targetFriend = f
			break
		}
	}
	m.mutex.RUnlock()
	if targetFriend == nil {
		return nil, fmt.Errorf("friend '%s' not found", nickname)
	}
	if !targetFriend.Approved {
		return nil, fmt.Errorf("you have not approved friend '%s' yet", nickname)
	}
	onionAddr := targetFriend.OnionAddress
	m.mutex.RLock()
	if peer, exists := m.peers[onionAddr]; exists {
		m.mutex.RUnlock()
		return peer, nil
	}
	m.mutex.RUnlock()
	dialer, err := m.tor.Dialer(m.ctx, nil)
	if err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(m.ctx, m.config.Tor.DialTimeout)
	defer cancel()
	conn, err := dialer.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", onionAddr, m.config.Tor.Port))
	if err != nil {
		return nil, err
	}
	secureConn, err := m.performClientHandshake(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	m.addPeer(onionAddr, secureConn)
	go m.managePeer(onionAddr, secureConn)
	return secureConn, nil
}

func (m *Messenger) updateLastSeen(peerOnion string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if friend, ok := m.friends[peerOnion]; ok {
		friend.LastSeen = time.Now().Unix()
	}
}

func (m *Messenger) addPeer(onion string, secureConn *SecureChannel) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if existing, exists := m.peers[onion]; exists {
		existing.conn.Close()
	}
	m.peers[onion] = secureConn
	if friend, ok := m.friends[onion]; ok {
		friend.LastSeen = time.Now().Unix()
		if m.callbacks.OnPeerConnected != nil {
			m.callbacks.OnPeerConnected(friend.Nickname)
		}
		if m.callbacks.OnFriendUpdate != nil {
			m.callbacks.OnFriendUpdate()
		}
	}
}

func (m *Messenger) removePeer(onion string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if conn, exists := m.peers[onion]; exists {
		conn.conn.Close()
		delete(m.peers, onion)
		if friend, ok := m.friends[onion]; ok {
			if m.callbacks.OnPeerDisconnected != nil {
				m.callbacks.OnPeerDisconnected(friend.Nickname)
			}
			if m.callbacks.OnFriendUpdate != nil {
				m.callbacks.OnFriendUpdate()
			}
		}
	}
}

func (m *Messenger) saveFriends() error {
	data, err := json.MarshalIndent(m.friends, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.friendsFilePath, data, 0600)
}

func (m *Messenger) loadFriends() error {
	if _, err := os.Stat(m.friendsFilePath); os.IsNotExist(err) {
		return nil
	}
	data, err := os.ReadFile(m.friendsFilePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &m.friends)
}

// ============================================================================
// MESSAGING SECTION
// ============================================================================

func (m *Messenger) SendMessage(nickname, content string) error {
	if len(content) == 0 || len(content) > 4096 {
		return errors.New("message content invalid length")
	}

	secureConn, err := m.connectToFriend(nickname)
	if err != nil {
		return err
	}

	msg := ChatMessage{From: m.id, Content: content, Time: time.Now().Unix()}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&msg); err != nil {
		return err
	}

	env := Envelope{
		Type:      TypeChatMsg,
		Data:      buf.Bytes(),
		Timestamp: time.Now().Unix(),
	}

	err = secureConn.Send(&env)

	SecureString(&msg.From)
	SecureString(&msg.Content)
	SecureWipe(buf.Bytes())

	return err
}

func (m *Messenger) BroadcastMessage(content string) {
	onlineFriends := m.GetOnlineFriends()
	if len(onlineFriends) == 0 {
		fmt.Printf("\r\033[KNo online friends to broadcast to.\n> ")
		return
	}
	for _, nickname := range onlineFriends {
		go func(nick string) {
			if err := m.SendMessage(nick, content); err != nil {
				fmt.Printf("\r\033[KFailed to send broadcast to %s: %v\n> ", nick, err)
			}
		}(nickname)
	}

	SecureString(&content)
}

func (m *Messenger) RotateKeyWithFriend(nickname string) error {
	m.mutex.RLock()
	var peerOnion string
	for onion, friend := range m.friends {
		if friend.Nickname == nickname {
			peerOnion = onion
			break
		}
	}
	m.mutex.RUnlock()

	if peerOnion == "" {
		return fmt.Errorf("friend '%s' not found", nickname)
	}

	return m.initiateKeyRotation(peerOnion)
}

// ============================================================================
// QR CODE AND UTILITY SECTION
// ============================================================================

func (m *Messenger) ShowQRCode() {
	obj := qrcodeTerminal.New()
	obj.Get(m.onion).Print()
	fmt.Printf("📱 Scan this QR code to share your onion address: %s\n", m.onion)
}

func (m *Messenger) AddFriendFromQR(qrData string) error {
	qrData = strings.TrimSpace(qrData)

	if !strings.HasSuffix(qrData, ".onion") || len(qrData) < 60 {
		return errors.New("invalid onion address in QR data")
	}

	nickname := fmt.Sprintf("Friend-%s", qrData[:8])

	m.mutex.RLock()
	for _, f := range m.friends {
		if f.OnionAddress == qrData {
			m.mutex.RUnlock()
			return fmt.Errorf("friend with onion address %s already exists as %s", qrData[:16]+"...", f.Nickname)
		}
	}
	m.mutex.RUnlock()

	return m.AddFriend(qrData, nickname)
}

func (m *Messenger) ScanQRFromFile(filePath string) error {
	imgdata, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	img, _, err := image.Decode(bytes.NewReader(imgdata))
	if err != nil {
		return fmt.Errorf("failed to decode image: %v", err)
	}

	qrCodes, err := goqr.Recognize(img)
	if err != nil {
		return fmt.Errorf("failed to recognize QR code: %v", err)
	}

	if len(qrCodes) == 0 {
		return errors.New("no QR codes found in image")
	}

	for _, qrCode := range qrCodes {
		data := string(qrCode.Payload)
		if strings.HasSuffix(data, ".onion") {
			return m.AddFriendFromQR(data)
		}
	}

	return errors.New("no valid onion addresses found in QR codes")
}

func (m *Messenger) DisplayFingerprints(nickname string) error {
	m.mutex.RLock()
	var friend *Friend
	for _, f := range m.friends {
		if f.Nickname == nickname {
			friend = f
			break
		}
	}
	m.mutex.RUnlock()

	if friend == nil {
		return fmt.Errorf("friend '%s' not found", nickname)
	}

	myFingerprint := GenerateFingerprint(m.onion)
	friendFingerprint := GenerateFingerprint(friend.OnionAddress)

	fmt.Printf("\n\r\033[K🔒 Fingerprint Verification for %s:\n", nickname)
	fmt.Println("--------------------------------------------------------------------")
	fmt.Printf("Your Fingerprint:\n  \033[1;33m%s\033[0m\n\n", myFingerprint)
	fmt.Printf("%s's Fingerprint:\n  \033[1;36m%s\033[0m\n", nickname, friendFingerprint)
	fmt.Println("--------------------------------------------------------------------")
	fmt.Println("🗣️  Please verify this fingerprint with your friend through a separate, trusted channel (like a phone call).")
	return nil
}

// ============================================================================
// MESSENGER UTILITY METHODS SECTION
// ============================================================================

func (m *Messenger) SetCallbacks(callbacks *MessengerCallbacks) { m.callbacks = callbacks }
func (m *Messenger) GetOnionAddress() string                    { return m.onion }
func (m *Messenger) GetUsername() string                        { return m.id }
func (m *Messenger) IsReady() bool {
	m.readyMutex.RLock()
	defer m.readyMutex.RUnlock()
	return m.ready
}

func (m *Messenger) GetFriends() map[string]*Friend {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	friends := make(map[string]*Friend)
	for k, v := range m.friends {
		friends[k] = &Friend{
			OnionAddress: v.OnionAddress,
			Nickname:     v.Nickname,
			Approved:     v.Approved,
			LastSeen:     v.LastSeen,
		}
	}
	return friends
}

func (m *Messenger) GetOnlineFriends() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	var online []string
	for onion, friend := range m.friends {
		if friend.Approved {
			if _, isOnline := m.peers[onion]; isOnline {
				online = append(online, friend.Nickname)
			}
		}
	}
	return online
}

func (m *Messenger) listFriends() {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if len(m.friends) == 0 {
		fmt.Println("📭 Your friend list is empty. Use /add to add someone.")
		return
	}
	fmt.Println("--- Friend List ---")
	fmt.Println("(Use /fingerprint <nickname> to verify a friend's identity)")
	for _, f := range m.friends {
		approvalStatus := "\033[33m⏳ Pending\033[0m"
		if f.Approved {
			approvalStatus = "\033[32m✅ Approved\033[0m"
		}
		var onlineStatus string
		if _, online := m.peers[f.OnionAddress]; online {
			onlineStatus = "\033[1;32m🟢 Online\033[0m"
		} else {
			if f.LastSeen == 0 {
				onlineStatus = "\033[1;31m⚫ Offline\033[0m"
			} else {
				lastSeenDuration := time.Since(time.Unix(f.LastSeen, 0))
				if lastSeenDuration > 24*time.Hour {
					onlineStatus = "\033[1;31m⚫ Offline\033[0m"
				} else {
					onlineStatus = fmt.Sprintf("\033[37m⚪ Seen %v ago\033[0m", lastSeenDuration.Round(time.Minute))
				}
			}
		}
		fmt.Printf("• %-20s (%s) - [%s]\n", f.Nickname, approvalStatus, onlineStatus)
	}
}

func (m *Messenger) Close() {
	fmt.Println("\n👋 Shutting down...")
	m.cancel()

	if m.dummyTrafficGenerator != nil {
		m.dummyTrafficGenerator.Stop()
	}

	if m.listener != nil {
		m.listener.Close()
	}
	m.mutex.Lock()
	for _, peer := range m.peers {
		peer.conn.Close()
	}
	m.mutex.Unlock()

	if m.keyManager != nil {
		m.keyManager.Close()
	}
	if m.sessionManager != nil {
		m.sessionManager.Close()
	}

	if m.tor != nil {
		m.tor.Close()
	}
	os.Exit(0)
}

// ============================================================================
// CLI INTERFACE SECTION
// ============================================================================

func runCLI(messenger *Messenger) {
	callbacks := &MessengerCallbacks{
		OnMessageReceived: func(msg ChatMessage) {
			timeStr := time.Unix(msg.Time, 0).Format("15:04")
			fmt.Printf("\r\033[K💬 [%s] %s: %s\n> ", timeStr, msg.From, msg.Content)

			SecureString(&msg.From)
			SecureString(&msg.Content)
		},
		OnPeerConnected: func(nickname string) {
			fmt.Printf("\r\033[K✅ %s is now online.\n> ", nickname)
		},
		OnPeerDisconnected: func(nickname string) {
			fmt.Printf("\r\033[K❌ %s has gone offline.\n> ", nickname)
		},
		OnApprovalRequested: func(nickname string) {
			fmt.Printf("\r\033[K🤝 %s wants to connect! Use `/approve %s` to accept.\n> ", nickname, nickname)
		},
		OnKeyRotated: func(nickname string) {
			fmt.Printf("\r\033[K🔄 Key rotated with %s for enhanced security.\n> ", nickname)
		},
	}
	messenger.SetCallbacks(callbacks)

	fmt.Printf("🚀 PMessenger %s\n", Version)
	fmt.Printf("👤 Username: %s\n", messenger.id)
	fmt.Printf("🧅 Your Onion Address: \033[1;32m%s\033[0m\n", messenger.onion)
	fmt.Println("\nCommands:")
	fmt.Println("  /add <onion> <nickname>   - Add a friend")
	fmt.Println("  /approve <nickname>       - Approve a friend request")
	fmt.Println("  /friends                  - List all friends")
	fmt.Println("  /remove <nickname>        - Remove a friend")
	fmt.Println("  /chat <nickname> <msg>    - Send a private message")
	fmt.Println("  /broadcast <msg>          - Send to all approved online friends")
	fmt.Println("  /rotate <nickname>        - Force key rotation with friend")
	fmt.Println("  /fingerprint <nickname>   - Verify friend's identity")
	fmt.Println("  /qr                       - Show your onion address as QR code")
	fmt.Println("  /code <qr_data>           - Add friend from QR code data")
	fmt.Println("  /quit                     - Exit the application")

	go messenger.acceptConnections()
	go messenger.startKeyRotationScheduler()
	messenger.dummyTrafficGenerator.Start()
	messenger.handleInput()
}

func (m *Messenger) handleInput() {
	scanner := bufio.NewScanner(os.Stdin)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		m.Close()
	}()
	fmt.Print("> ")
	for scanner.Scan() {
		if m.ctx.Err() != nil {
			return
		}
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			fmt.Print("> ")
			continue
		}
		parts := strings.Fields(input)
		command := parts[0]
		args := parts[1:]
		var err error
		switch command {
		case "/add":
			if len(args) != 2 {
				err = errors.New("usage: /add <onion> <nickname>")
			} else {
				err = m.AddFriend(args[0], args[1])
			}
		case "/approve":
			if len(args) != 1 {
				err = errors.New("usage: /approve <nickname>")
			} else {
				err = m.ApproveFriend(args[0])
			}
		case "/remove":
			if len(args) != 1 {
				err = errors.New("usage: /remove <nickname>")
			} else {
				err = m.RemoveFriend(args[0])
			}
		case "/friends":
			m.listFriends()
		case "/chat":
			if len(args) < 2 {
				err = errors.New("usage: /chat <nickname> <message>")
			} else {
				message := strings.Join(args[1:], " ")
				go m.SendMessage(args[0], message)
				SecureString(&message)
			}
		case "/broadcast":
			if len(args) < 1 {
				err = errors.New("usage: /broadcast <message>")
			} else {
				message := strings.Join(args, " ")
				go m.BroadcastMessage(message)
			}
		case "/rotate":
			if len(args) != 1 {
				err = errors.New("usage: /rotate <nickname>")
			} else {
				err = m.RotateKeyWithFriend(args[0])
			}
		case "/fingerprint":
			if len(args) != 1 {
				err = errors.New("usage: /fingerprint <nickname>")
			} else {
				err = m.DisplayFingerprints(args[0])
			}
		case "/qr":
			m.ShowQRCode()
		case "/code":
			if len(args) < 1 {
				err = errors.New("usage: /code <qr_data>")
			} else {
				qrData := strings.Join(args, " ")
				err = m.AddFriendFromQR(qrData)
				if err == nil {
					fmt.Printf("✅ Friend added from QR code data\n")
				}
			}
		case "/quit":
			m.Close()
			return
		default:
			err = errors.New("unknown command")
		}
		if err != nil {
			fmt.Printf("\r\033[K❌ Error: %v\n", err)
		}

		SecureString(&input)
		for i := range parts {
			SecureString(&parts[i])
		}
		for i := range args {
			SecureString(&args[i])
		}

		fmt.Print("> ")
	}
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

func main() {
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Configuration error: %v\n", err)
		fmt.Println("\nExample usage:")
		fmt.Println("  ./pmessenger --user alice")
		fmt.Println("  PMESSENGER_USER=alice ./pmessenger")
		fmt.Println("  ./pmessenger --config ./pmessenger.yaml")
		os.Exit(1)
	}

	log.Printf("🔧 Configuration loaded: user=%s, verbose=%v", config.User, config.Verbose)

	messenger, err := NewMessenger(config)
	if err != nil {
		log.Fatalf("Failed to start messenger: %v", err)
	}
	defer messenger.Close()

	go messenger.startCircuitRotation(config.Tor.CircuitRotateInterval)

	runCLI(messenger)
}
