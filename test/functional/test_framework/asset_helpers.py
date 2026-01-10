from decimal import ROUND_UP, Decimal
import struct
from collections import defaultdict
from test_framework.messages import (
    ser_compact_size,
    ser_string,
)
from test_framework.blocktools import (
    wentuno_TX_VERSION_ALLOCATION_BURN_TO_wentuno,
    wentuno_TX_VERSION_wentuno_BURN_TO_ALLOCATION,
    wentuno_TX_VERSION_ALLOCATION_MINT,
    wentuno_TX_VERSION_ALLOCATION_BURN_TO_NEVM,
    wentuno_TX_VERSION_ALLOCATION_SEND,
)
################################################################################
# Minimal stubs mirroring wentuno classes:
################################################################################

DUST_THRESHOLD = Decimal('0.00000546')

def ser_varint(n):
    result = bytearray()
    while True:
        byte = n & 0x7F
        if result:
            byte |= 0x80
        result.insert(0, byte)
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
    return bytes(result)

def compress_amount_64bit(amount) -> bytes:
    if isinstance(amount, Decimal):
        amount = int(amount * 100000000)
    elif not isinstance(amount, int):
        amount = int(float(amount) * 100000000)

    if amount == 0:
        return ser_varint(0)

    e, n = 0, amount
    while (n % 10) == 0 and e < 9:
        n //= 10
        e += 1

    if e < 9:
        d = n % 10
        n //= 10
        code = 1 + (n * 9 + d - 1) * 10 + e
    else:
        code = 1 + (n - 1) * 10 + 9

    return ser_varint(code)

class AssetOutValue:
    def __init__(self, n=0, nValue=0):
        self.n = n
        self.nValue = nValue

    def serialize(self):
        return ser_compact_size(self.n) + compress_amount_64bit(self.nValue)

class AssetOut:
    def __init__(self, key=0, values=None):
        self.key = key
        self.values = values or []

    def serialize(self):
        out = ser_varint(self.key)
        out += ser_compact_size(len(self.values))
        for av in self.values:
            out += av.serialize()
        return out

class CAssetAllocation:
    def __init__(self, voutAssets=None):
        self.voutAssets = voutAssets or []

    def serialize(self):
        out = ser_compact_size(len(self.voutAssets))
        for ao in self.voutAssets:
            out += ao.serialize()
        return out

class CMintwentuno(CAssetAllocation):
    def __init__(self, voutAssets=None, spv_proof=None):
        super().__init__(voutAssets=voutAssets)
        spv_proof = spv_proof or {}
        self.txHash = spv_proof.get("txHash", b"\x00"*32)
        self.txValue = spv_proof.get("txValue", b"\x00"*20)
        self.txPos = spv_proof.get("txPos", 0)
        self.txBlockHash = spv_proof.get("txBlockHash", b"\x00"*32)
        self.txParentNodes = spv_proof.get("txParentNodes", b"")
        self.txPath = spv_proof.get("txPath", b"")
        self.posReceipt = spv_proof.get("posReceipt", 0)
        self.receiptParentNodes = spv_proof.get("receiptParentNodes", b"")
        self.txRoot = spv_proof.get("txRoot", b"\x00"*32)
        self.receiptRoot = spv_proof.get("receiptRoot", b"\x00"*32)

    def serialize(self):
        out = super().serialize()

        assert len(self.txHash) == 32, "txHash must be 32 bytes"
        assert len(self.txBlockHash) == 32, "txBlockHash must be 32 bytes"
        assert len(self.txRoot) == 32, "txRoot must be 32 bytes"
        assert len(self.receiptRoot) == 32, "receiptRoot must be 32 bytes"

        out += self.txHash
        out += self.txBlockHash
        out += struct.pack("<H", self.txPos)
        out += ser_string(self.txParentNodes)
        out += ser_string(self.txPath)
        out += struct.pack("<H", self.posReceipt)
        out += ser_string(self.receiptParentNodes)
        out += self.txRoot
        out += self.receiptRoot
        return out



class CBurnwentuno(CAssetAllocation):
    def __init__(self, voutAssets=None, nevm_address=b''):
        super().__init__(voutAssets=voutAssets)
        self.vchNEVMAddress = nevm_address

    def serialize(self):
        return super().serialize() + ser_string(self.vchNEVMAddress)


################################################################################
# 3) Putting it all together in a param-based "SDK" function
################################################################################

def create_allocation_data(tx_type,
                         vout_assets=None,
                         # For CMintwentuno:
                         spv_proof=None,  # Pass the entire SPV proof as one object
                         # For CBurnwentuno:
                         vchNEVMAddress=None
                         ) -> str:
    """Create serialized allocation data for a wentuno transaction.
    
    Args:
        allocation_type: Type of allocation ("allocation", "mint", or "burn")
        vout_assets: List of AssetOut objects to include
        spv_proof: For mint operations, the SPV proof data (entire object)
        vchNEVMAddress: For burn operations, the NEVM address
        
    Returns:
        Hex-encoded serialized allocation data
    """
    if vout_assets is None:
        vout_assets = []
    if tx_type == wentuno_TX_VERSION_ALLOCATION_SEND or tx_type == wentuno_TX_VERSION_ALLOCATION_BURN_TO_wentuno or tx_type == wentuno_TX_VERSION_wentuno_BURN_TO_ALLOCATION:
        obj = CAssetAllocation(voutAssets=vout_assets)
    elif tx_type == wentuno_TX_VERSION_ALLOCATION_MINT:
        obj = CMintwentuno(voutAssets=vout_assets, spv_proof=spv_proof)
    elif tx_type == wentuno_TX_VERSION_ALLOCATION_BURN_TO_NEVM:
        obj = CBurnwentuno(voutAssets=vout_assets, nevm_address=vchNEVMAddress)
    else:
        raise ValueError(f"Unknown allocation type: {tx_type}")
    
    # Serialize the data
    raw_data = obj.serialize()
    return raw_data.hex()

def attach_allocation_data_to_tx(node, inputs, outputs):
    """
    Create raw tx with allocation data, then modify it with wentuno RPC if needed
    """
    # Clean up inputs to only include required fields
    cleaned_inputs = []
    for inp in inputs:
        cleaned_inputs.append({
            "txid": inp["txid"],
            "vout": inp["vout"]
        })
    
    # Create the raw transaction
    rawtx = node.createrawtransaction(
        inputs=cleaned_inputs,
        outputs=outputs,
    )
    # Sign the transaction
    sign_res = node.signrawtransactionwithwallet(rawtx)
    return sign_res["hex"]

class CoinSelector:
    def __init__(self, node, max_inputs=1000):
        self.node = node
        self.max_inputs = max_inputs
        self.selected_utxos = []
        self.total_WUNO = Decimal('0')
        self.total_assets = {}

    def analyze_utxo(self, utxo):
        WUNO_value = Decimal(str(utxo['amount']))
        asset = None
        if 'asset_guid' in utxo:
            asset = {'asset_guid': utxo['asset_guid'], 'asset_amount': utxo['asset_amount']}
        return WUNO_value, asset

    def select_optimal_inputs(self, WUNO_target, asset_targets=None):
        asset_targets = asset_targets or {}
        asset_targets = {int(k): v for k, v in asset_targets.items()}
        self.selected_utxos = []
        self.total_WUNO = Decimal('0')
        self.total_assets = {}

        all_utxos = sorted(self.node.listunspent(), key=lambda x: -x['amount'])

        asset_utxos = []
        WUNO_only_utxos = []

        for utxo in all_utxos:
            WUNO_value, asset = self.analyze_utxo(utxo)
            if asset:
                asset_utxos.append((utxo, WUNO_value, asset))
            else:
                WUNO_only_utxos.append((utxo, WUNO_value))

        # First select asset utxos required explicitly for asset targets
        for utxo, WUNO_value, asset in asset_utxos:
            if len(self.selected_utxos) >= self.max_inputs:
                break

            guid = asset['asset_guid']
            if guid not in asset_targets:
                continue  # skip if asset isn't targeted explicitly yet

            if self.total_assets.get(guid, Decimal('0')) >= asset_targets[guid]:
                continue  # already fulfilled

            self.selected_utxos.append({"txid": utxo["txid"], "vout": utxo["vout"]})
            self.total_WUNO += WUNO_value
            self.total_assets[guid] = self.total_assets.get(guid, Decimal('0')) + asset['asset_amount']

            if all(self.total_assets.get(g, 0) >= amt for g, amt in asset_targets.items()):
                break  # All explicit asset targets met

        # WUNO-only UTXOs next
        if self.total_WUNO < WUNO_target:
            for utxo, WUNO_value in WUNO_only_utxos:
                if len(self.selected_utxos) >= self.max_inputs:
                    break
                self.selected_utxos.append({"txid": utxo["txid"], "vout": utxo["vout"]})
                self.total_WUNO += WUNO_value

                if self.total_WUNO >= WUNO_target:
                    break

        # Still need more WUNO? Then use asset UTXOs again (but track unintended assets)
        if self.total_WUNO < WUNO_target:
            for utxo, WUNO_value, asset in asset_utxos:
                if len(self.selected_utxos) >= self.max_inputs:
                    break
                if {"txid": utxo["txid"], "vout": utxo["vout"]} in self.selected_utxos:
                    continue  # already added above

                self.selected_utxos.append({"txid": utxo["txid"], "vout": utxo["vout"]})
                self.total_WUNO += WUNO_value

                # Track unintended assets here
                guid = asset['asset_guid']
                self.total_assets[guid] = self.total_assets.get(guid, Decimal('0')) + asset['asset_amount']

                if self.total_WUNO >= WUNO_target:
                    break

        # Final validations
        if self.total_WUNO < WUNO_target:
            raise ValueError(f"Not enough WUNO: need {WUNO_target}, have {self.total_WUNO}")

        for guid, amount in asset_targets.items():
            if self.total_assets.get(guid, Decimal('0')) < amount:
                raise ValueError(f"Not enough asset {guid}: need {amount}, have {self.total_assets.get(guid, Decimal('0'))}")

    def select_coins_for_transaction(self, WUNO_amount, asset_amounts=None, fees=None):
        asset_amounts = asset_amounts or []
        accumulated_assets = defaultdict(Decimal)
        for guid, amount, _ in asset_amounts:
            accumulated_assets[int(guid)] += amount

        asset_amounts = dict(accumulated_assets)
        initial_fee = fees if fees else Decimal('0.0001')
        num_asset_change_outputs = len([guid for guid in asset_amounts if asset_amounts[guid] > 0])
        total_WUNO_needed = Decimal(WUNO_amount) + initial_fee + (DUST_THRESHOLD * num_asset_change_outputs)
        self.select_optimal_inputs(total_WUNO_needed, asset_amounts)
        if self.total_WUNO < total_WUNO_needed:
            raise ValueError(f"Not enough WUNO: need {total_WUNO_needed}, have {self.total_WUNO}")
        WUNO_change = self.total_WUNO - total_WUNO_needed
        WUNO_change = WUNO_change if WUNO_change >= DUST_THRESHOLD else Decimal('0')
        asset_changes = {
            guid: (self.total_assets[guid] - asset_amounts.get(guid, Decimal('0')))
            for guid in self.total_assets
            if (self.total_assets[guid] - asset_amounts.get(guid, Decimal('0'))) > 0
        }
        print(f"Selected UTXOs: {self.selected_utxos}")
        print(f"Total WUNO: {self.total_WUNO}")
        print(f"Total assets collected: {self.total_assets}")
        print(f"Asset changes calculated: {asset_changes}")

        return True, self.selected_utxos, WUNO_change, asset_changes

def create_transaction_with_selector(node, tx_type, WUNO_amount=Decimal('0'), WUNO_destination=None,
                              asset_amounts=None, fees=None, nevm_address=None,
                              spv_proof=None):
    """
    Create a transaction with the specified type using CoinSelector for input selection
    
    Args:
        node: The node to use for coin selection and transaction creation
        tx_type: One of the wentuno_TX_VERSION_* constants
        WUNO_amount: Amount of WUNO to send/burn (for WUNO->WUNOX conversion)
        WUNO_destination: Destination for WUNO to send/burn  (for WUNOX->WUNO conversion)
        asset_amounts: Triple of {guid, amount, destination} for asset operations
        fees: Optional override for fee calculation
        destinations: Dict of {guid: address} for asset send operations
        nevm_address: NEVM address for BURN_TO_NEVM operations
        spv_proof: SPV proof for mint operations
        
    Returns:
        Hex string of the signed transaction
    """
    # Initialize asset tracker for changes
    asset_outputs = []
    nevm_address_bin = None
    # Create coin selector and select inputs
    selector = CoinSelector(node)
    if tx_type == wentuno_TX_VERSION_wentuno_BURN_TO_ALLOCATION or tx_type == wentuno_TX_VERSION_ALLOCATION_MINT:
        success, inputs, change, asset_changes = selector.select_coins_for_transaction(
            WUNO_amount, fees=fees
        )
    else:
        success, inputs, change, asset_changes = selector.select_coins_for_transaction(
            WUNO_amount, asset_amounts, fees
        )

    if not success:
        raise ValueError(f"Failed to select coins for transaction type {tx_type}")
    
    outputs = []
    if WUNO_destination and WUNO_amount > 0:
        outputs.append({WUNO_destination: float(WUNO_amount)})

    # Handle WUNO change if any (always comes next)
    if change > 0:
        change_address = node.getnewaddress()
        outputs.append({change_address: float(change)})

    # Add asset change outputs for all transaction types
    for guid, amount in asset_changes.items():
        change_address = node.getnewaddress()
        outputs.append({change_address: float(DUST_THRESHOLD)})
        change_out = AssetOut(
            key=int(guid),
            values=[AssetOutValue(n=len(outputs)-1, nValue=amount)]
        )
        asset_outputs.append(change_out)

    # Now add all other outputs and track their indices
    # Handle each transaction type
    if tx_type == wentuno_TX_VERSION_wentuno_BURN_TO_ALLOCATION:
        guid, amount, destination = next(iter(asset_amounts))
        outputs.append({destination: float(DUST_THRESHOLD)})
        WUNOx_out = AssetOut(
            key=guid,
            values=[AssetOutValue(n=len(outputs)-1, nValue=amount)]
        )
        asset_outputs.append(WUNOx_out)
        data_hex = create_allocation_data(tx_type, vout_assets=asset_outputs)
        outputs.append({"data_amount": float(amount)})
    
    elif tx_type == wentuno_TX_VERSION_ALLOCATION_BURN_TO_wentuno:
        guid, amount, destination = next(iter(asset_amounts))
        # Replace normal WUNO output with burn WUNO output
        if WUNO_destination and WUNO_amount > 0:
            outputs.pop(0)
        # WUNO has to exist at vout[0]
        outputs.insert(0, {destination: float(amount)})
        # if regular WUNO spend add it to the end
        if WUNO_destination and WUNO_amount > 0:
            outputs.append({WUNO_destination: float(WUNO_amount)})
        WUNOx_out = AssetOut(
            key=guid,
            values=[AssetOutValue(n=len(outputs), nValue=amount)]
        )
        asset_outputs.append(WUNOx_out)
    
    elif tx_type == wentuno_TX_VERSION_ALLOCATION_BURN_TO_NEVM:
        # For NEVM burn, we don't create regular outputs for the assets
        guid, amount, destination = next(iter(asset_amounts))
        # Validate and format NEVM address
        if not nevm_address or not isinstance(nevm_address, str):
            raise ValueError("nevm_address must be provided as a string for BURN_TO_NEVM")
        if nevm_address.startswith('0x'):
            nevm_address = nevm_address[2:]
        try:
            nevm_address_bin = bytes.fromhex(nevm_address)
        except ValueError:
            raise ValueError(f"Invalid NEVM address provided: {nevm_address}")
        burn_out = AssetOut(
            key=int(guid),
            values=[AssetOutValue(n=len(outputs), nValue=amount)]
        )
        asset_outputs.append(burn_out)
        
    
    elif tx_type == wentuno_TX_VERSION_ALLOCATION_SEND:
        # Add all destination outputs first
        for guid, amount, destination in asset_amounts:
            if not destination:
                raise ValueError(f"Destination address not found for asset {guid}")
            
            # Add destination output
            outputs.append({destination: float(DUST_THRESHOLD)})
            
            # Create asset output referencing the correct output index
            send_out = AssetOut(
                key=guid,
                values=[AssetOutValue(n=len(outputs)-1, nValue=amount)]
            )
            asset_outputs.append(send_out)
    
    elif tx_type == wentuno_TX_VERSION_ALLOCATION_MINT:
        # Add destination output for minted assets
        guid, amount, destination = next(iter(asset_amounts))
        outputs.append({destination: float(DUST_THRESHOLD)})
        
        # Create mint output - the asset goes to the destination output
        mint_out = AssetOut(
            key=guid,
            values=[AssetOutValue(n=len(outputs)-1, nValue=amount)]
        )
        asset_outputs.append(mint_out)
    

    data_hex = create_allocation_data(tx_type, vout_assets=asset_outputs,
                                    vchNEVMAddress=nevm_address_bin, spv_proof=spv_proof)
    outputs.append({"data": data_hex})
    outputs.append({"data_version": tx_type})
    
    # Create and sign the transaction
    tx_hex = attach_allocation_data_to_tx(node, inputs, outputs)
    return tx_hex

def verify_tx_outputs(node, txid, tx_type, asset_details=None):
    """Efficiently verify transaction outputs based on wentuno transaction type."""
    asset_details = asset_details or {}
    utxos = node.listunspent()
    def utxo_exists(asset_guid=None, asset_amount=None, WUNO_amt=None, destination=None):
        for utxo in utxos:
            if utxo['txid'] != txid:
                continue
            if WUNO_amt and Decimal(str(utxo['amount'])) != Decimal(str(WUNO_amt)):
                continue
            if destination and utxo['address'] != destination:
                continue
            if asset_guid and asset_amount:
                if (int(utxo.get('asset_guid', -1)) == asset_guid and
                    Decimal(str(utxo.get('asset_amount', '0'))) == Decimal(str(asset_amount))):
                    return True
                continue
            elif not asset_guid and not asset_amount:
                return True
        return False

    if tx_type == wentuno_TX_VERSION_ALLOCATION_SEND:
        for guid, amount, destination in asset_details:
            if not utxo_exists(asset_guid=guid, asset_amount=amount, WUNO_amt=DUST_THRESHOLD, destination=destination):
                raise AssertionError(f"Asset output not found: txid={txid}, guid={guid}, amount={amount}")

    elif tx_type == wentuno_TX_VERSION_ALLOCATION_MINT:
        for guid, amount, destination  in asset_details:
            if not utxo_exists(asset_guid=guid, asset_amount=amount, WUNO_amt=DUST_THRESHOLD, destination=destination):
                raise AssertionError(f"Minted asset not found: txid={txid}, guid={guid}, amount={amount}")

    elif tx_type == wentuno_TX_VERSION_ALLOCATION_BURN_TO_NEVM:
        for guid, amount, destination  in asset_details:
            if utxo_exists(asset_guid=guid, asset_amount=amount, destination=destination):
                raise AssertionError(f"Burned asset still found in UTXO: txid={txid}, guid={guid}, amount={amount}")

    elif tx_type == wentuno_TX_VERSION_wentuno_BURN_TO_ALLOCATION:
        for guid, amount, destination  in asset_details:
            if not utxo_exists(asset_guid=guid, asset_amount=amount, destination=destination):
                raise AssertionError(f"WUNOX output not found in UTXO: txid={txid}, guid={guid}, amount={amount}")

    elif tx_type == wentuno_TX_VERSION_ALLOCATION_BURN_TO_wentuno:
        for guid, amount, destination  in asset_details:
            if utxo_exists(asset_guid=guid, asset_amount=amount, destination=destination):
                raise AssertionError(f"WUNO output still found in UTXO: txid={txid}, guid={guid}, amount={amount}")

    else:
        raise ValueError("Unknown transaction type")