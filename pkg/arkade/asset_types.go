package arkade

// AssetInputType represents the type of an asset input
type AssetInputType byte

const (
	AssetInputTypeLocal  AssetInputType = 0x01
	AssetInputTypeIntent AssetInputType = 0x02
)

// AssetOutputType represents the type of an asset output
type AssetOutputType byte

const (
	AssetOutputTypeLocal  AssetOutputType = 0x01
	AssetOutputTypeIntent AssetOutputType = 0x02
)

// AssetID identifies an asset by its genesis transaction and group index
type AssetID struct {
	Txid [32]byte
	Gidx uint16
}

// AssetInput represents an input in an asset group
type AssetInput struct {
	Type        AssetInputType
	InputIndex  uint32   // for LOCAL inputs: transaction input index
	Txid        [32]byte // for INTENT inputs: intent transaction ID
	OutputIndex uint32   // for INTENT inputs: output index in intent tx
	Amount      uint64
}

// AssetOutput represents an output in an asset group
type AssetOutput struct {
	Type        AssetOutputType
	OutputIndex uint32 // output index
	Amount      uint64
}

// AssetGroup represents a group of assets in the packet
type AssetGroup struct {
	AssetID      AssetID
	Control      *AssetID     // nil if no control asset
	MetadataHash [32]byte     // immutable metadata Merkle root
	Inputs       []AssetInput
	Outputs      []AssetOutput
}

// InputAssetEntry represents an asset declared for a specific input
type InputAssetEntry struct {
	AssetID AssetID
	Amount  uint64
}

// OutputAssetEntry represents an asset assigned to a specific output
type OutputAssetEntry struct {
	AssetID AssetID
	Amount  uint64
}

// AssetPacket contains the full Arkade Asset V1 packet data
type AssetPacket struct {
	Groups       []AssetGroup
	InputAssets  map[uint32][]InputAssetEntry  // keyed by input index
	OutputAssets map[uint32][]OutputAssetEntry // keyed by output index
}
