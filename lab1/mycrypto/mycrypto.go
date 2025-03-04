package mycrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// --- Константы ---
// Общие параметры для AES
const (
	AESBlockSize = 16
	AESKeySize16 = 16
	AESKeySize24 = 24
	AESKeySize32 = 32
)

// Параметры для режима CTR (формат CTR = nonce || IV || counter)
const (
	NonceSize   = 4
	IVSize      = 4
	CounterSize = 8
)

// Константы режимов шифрования и типов паддинга.
const (
	ModeECB = "ECB"
	ModeCBC = "CBC"
	ModeCFB = "CFB"
	ModeOFB = "OFB"
	ModeCTR = "CTR"

	PaddingPKCS7 = "PKCS7"
	PaddingNON   = "NON"
)

// MyCipher представляет конфигурацию для блочного шифрования с потоковым интерфейсом.
// Внутреннее состояние (например, IV или счётчик) хранится отдельно для шифрования/дешифрования одного сообщения.
type MyCipher struct {
	key       []byte
	mode      string
	aesBlock  cipher.Block
	lastBlock []byte
	blockSize int
	nonce     []byte
}

// SetKey устанавливает ключ и инициализирует AES‑блочный шифр
func (mc *MyCipher) SetKey(newkey []byte) error {
	if len(newkey) != AESKeySize16 && len(newkey) != AESKeySize24 && len(newkey) != AESKeySize32 {
		return fmt.Errorf("invalid key length: got %d, expected %d, %d, or %d", len(newkey), AESKeySize16, AESKeySize24, AESKeySize32)
	}
	var err error
	mc.key = newkey
	mc.aesBlock, err = aes.NewCipher(newkey)
	if err != nil {
		return err
	}
	mc.blockSize = mc.aesBlock.BlockSize() // всегда 16 байт для AES
	mc.lastBlock = nil
	return nil
}

// SetMode задает режим шифрования
func (mc *MyCipher) SetMode(newmode string) error {
	switch newmode {
	case ModeECB, ModeCBC, ModeCFB, ModeOFB, ModeCTR:
		mc.mode = newmode
		mc.lastBlock = nil
		return nil
	default:
		return fmt.Errorf("wrong mode [%s] detected", newmode)
	}
}

// BlockCipherEncrypt выполняет одноблочное шифрование с помощью AES
func (mc *MyCipher) BlockCipherEncrypt(data []byte) ([]byte, error) {
	if len(data) != mc.blockSize {
		return nil, fmt.Errorf("BlockCipherEncrypt: data length must be %d", mc.blockSize)
	}
	out := make([]byte, mc.blockSize)
	mc.aesBlock.Encrypt(out, data)
	return out, nil
}

// BlockCipherDecrypt выполняет одноблочное дешифрование.
func (mc *MyCipher) BlockCipherDecrypt(data []byte) ([]byte, error) {
	if len(data) != mc.blockSize {
		return nil, fmt.Errorf("BlockCipherDecrypt: data length must be %d", mc.blockSize)
	}
	out := make([]byte, mc.blockSize)
	mc.aesBlock.Decrypt(out, data)
	return out, nil
}

// ----- Общие функции паддинга -----

// pkcs7Pad добавляет PKCS7-паддинг к данным.
func Pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

// pkcs7Unpad удаляет PKCS7-паддинг.
func Pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded data")
	}
	padLen := int(data[len(data)-1])
	if padLen <= 0 || padLen > blockSize {
		return nil, errors.New("invalid padding")
	}
	// Проверяем корректность всех байтов паддинга.
	for i := 0; i < padLen; i++ {
		if data[len(data)-1-i] != byte(padLen) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}

// xorBytes выполняет операцию XOR двух срезов байтов одинаковой длины.
func xorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("xor: slices must have equal length")
	}
	res := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		res[i] = a[i] ^ b[i]
	}
	return res, nil
}

// Функция инкремента для части CTR, отвечающей за блоковый счетчик (CTR_BLOCK).
// Мы считаем, что CTR имеет формат: [nonce (4) || IV (4) || counter (8)]
func incBlockCTR(counter []byte) {
	// Инкрементируем последние 8 байт.
	for i := AESBlockSize - 1; i >= NonceSize+IVSize; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

// Функция INC_MSG для режима CTR – увеличивает поле IV (CTR_MSG) и сбрасывает счетчик блока.
func incMsgCTR(counter []byte) {
	for i := NonceSize + IVSize - 1; i >= NonceSize; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
	// Сбрасываем последние 8 байт (CTR_BLOCK) в ноль.
	for i := NonceSize + IVSize; i < AESBlockSize; i++ {
		counter[i] = 0
	}
}

// requiresIV возвращает true, если режим шифрования требует IV
func (mc *MyCipher) requiresIV() bool {
	switch mc.mode {
	case ModeECB:
		return false
	case ModeCBC, ModeCFB, ModeCTR, ModeOFB:
		return true
	default:
		return true
	}
}

// ----- Потоковый интерфейс -----

// ProcessBlockEncrypt осуществляет шифрование одного блока (или части блока) с учётом режима и паддинга.
// Для режимов CBC и ECB с PKCS7 паддингом ожидается, что неполный блок передается только в финальном вызове.
func (mc *MyCipher) ProcessBlockEncrypt(data []byte, isFinalBlock bool, padding string) ([]byte, error) {
	// Проверка допустимости типа паддинга.
	if padding != PaddingPKCS7 && padding != PaddingNON {
		return nil, fmt.Errorf("unsupported padding: %s", padding)
	}
	var result []byte
	switch mc.mode {
	case ModeECB:
		// В режиме ECB все блоки должны иметь длину blockSize.
		if isFinalBlock && padding == PaddingPKCS7 {
			data = Pkcs7Pad(data, mc.blockSize)
		} else if len(data) != mc.blockSize {
			return nil, fmt.Errorf("ECB: data block length must be %d", mc.blockSize)
		}
		enc, err := mc.BlockCipherEncrypt(data)
		if err != nil {
			return nil, err
		}
		result = append(result, enc...)
		return result, nil

	case ModeCBC:
		// Если lastBlock не задан, генерируем IV и сохраняем его.
		if mc.lastBlock == nil {
			iv := make([]byte, mc.blockSize)
			if n, err := rand.Read(iv); err != nil || n != mc.blockSize {
				return nil, errors.New("Failed to generate IV")
			}
			mc.lastBlock = iv
			// При шифровании IV прикрепляем в начало результата.
			result = append(result, iv...)
		}
		if isFinalBlock && padding == PaddingPKCS7 {
			data = Pkcs7Pad(data, mc.blockSize)
		} else if len(data) != mc.blockSize {
			return nil, fmt.Errorf("CBC: data block length must be %d", mc.blockSize)
		}
		xored, err := xorBytes(data, mc.lastBlock)
		if err != nil {
			return nil, err
		}
		enc, err := mc.BlockCipherEncrypt(xored)
		if err != nil {
			return nil, err
		}
		result = append(result, enc...)
		mc.lastBlock = enc
		return result, nil

	case ModeCFB:
		// Для режимов CFB, OFB, CTR используется паддинг NON.
		if padding != PaddingNON {
			return nil, errors.New("CFB mode does not support padding")
		}
		if mc.lastBlock == nil {
			iv := make([]byte, mc.blockSize)
			if n, err := rand.Read(iv); err != nil || n != mc.blockSize {
				return nil, errors.New("failed to generate IV")
			}
			mc.lastBlock = iv
			result = append(result, iv...)
		}
		encrypted, err := mc.BlockCipherEncrypt(mc.lastBlock)
		if err != nil {
			return nil, err
		}
		n := len(data)
		if n < mc.blockSize {
			encrypted = encrypted[:n]
		}
		xored, err := xorBytes(data, encrypted)
		if err != nil {
			return nil, err
		}
		result = append(result, xored...)
		if len(data) == mc.blockSize {
			mc.lastBlock = xored
		}
		return result, nil

	case ModeOFB:
		if padding != PaddingNON {
			return nil, errors.New("OFB mode does not support padding")
		}
		if mc.lastBlock == nil {
			iv := make([]byte, mc.blockSize)
			if n, err := rand.Read(iv); err != nil || n != mc.blockSize {
				return nil, errors.New("failed to generate IV")
			}
			mc.lastBlock = iv
			result = append(result, iv...)
		}
		encrypted, err := mc.BlockCipherEncrypt(mc.lastBlock)
		if err != nil {
			return nil, err
		}
		n := len(data)
		if n < mc.blockSize {
			encrypted = encrypted[:n]
		}
		xored, err := xorBytes(data, encrypted)
		if err != nil {
			return nil, err
		}
		result = append(result, xored...)
		mc.lastBlock = encrypted
		return result, nil

	case ModeCTR:
		if padding != PaddingNON {
			return nil, errors.New("CTR mode does not support padding")
		}
		if mc.lastBlock == nil {
			if mc.nonce == nil {
				nonce := make([]byte, NonceSize)
				if n, err := rand.Read(nonce); err != nil || n != NonceSize {
					return nil, errors.New("failed to generate nonce")
				}
				mc.nonce = nonce
			}
			newIV := make([]byte, IVSize)
			if n, err := rand.Read(newIV); err != nil || n != IVSize {
				return nil, errors.New("failed to generate IV for CTR")
			}
			counterBlock := make([]byte, CounterSize) // по умолчанию нули
			ctr := append(append(append([]byte{}, mc.nonce...), newIV...), counterBlock...)
			if len(ctr) != mc.blockSize {
				return nil, fmt.Errorf("CTR: invalid ctr length, got %d, expected %d", len(ctr), mc.blockSize)
			}
			mc.lastBlock = ctr
			result = append(result, ctr...)
		}
		counter := make([]byte, mc.blockSize)
		copy(counter, mc.lastBlock)
		keystream, err := mc.BlockCipherEncrypt(counter)
		if err != nil {
			return nil, err
		}
		n := len(data)
		if n < mc.blockSize {
			keystream = keystream[:n]
		}
		encrypted, err := xorBytes(data, keystream)
		if err != nil {
			return nil, err
		}
		result = append(result, encrypted...)
		if isFinalBlock {
			incMsgCTR(counter)
		} else {
			incBlockCTR(counter)
		}
		mc.lastBlock = counter
		return result, nil

	default:
		return nil, fmt.Errorf("unsupported mode: %s", mc.mode)
	}
}

// ProcessBlockDecrypt реализует потоковое дешифрование блока.
// Согласно заданию: если lastBlock == nil, то считаем первый блок входных данных IV и возвращаем пустой срез.
func (mc *MyCipher) ProcessBlockDecrypt(data []byte, isFinalBlock bool, padding string) ([]byte, error) {
	if padding != PaddingPKCS7 && padding != PaddingNON {
		return nil, fmt.Errorf("unsupported padding: %s", padding)
	}
	var result []byte
	switch mc.mode {
	case ModeECB:
		if len(data) != mc.blockSize {
			return nil, fmt.Errorf("ECB:ciphertext length must be %d", mc.blockSize)
		}
		decrypted, err := mc.BlockCipherDecrypt(data)
		if err != nil {
			return nil, err
		}
		result = append(result, decrypted...)
		if isFinalBlock && padding == PaddingPKCS7 {
			return Pkcs7Unpad(result, mc.blockSize)
		}
		return result, nil

	case ModeCBC:
		if len(data) != mc.blockSize {
			return nil, fmt.Errorf("CBC: ciphertext block length must be %d", mc.blockSize)
		}
		if mc.lastBlock == nil {
			if len(data) < mc.blockSize {
				return nil, errors.New("CBC Decrypt: ciphertext too short to contain IV")
			}
			mc.lastBlock = make([]byte, mc.blockSize)
			copy(mc.lastBlock, data[:mc.blockSize])
			return []byte{}, nil
		}
		decrypted, err := mc.BlockCipherDecrypt(data)
		if err != nil {
			return nil, err
		}
		plaintext, err := xorBytes(decrypted, mc.lastBlock)
		if err != nil {
			return nil, err
		}
		result = append(result, plaintext...)
		mc.lastBlock = make([]byte, mc.blockSize)
		copy(mc.lastBlock, data)
		if isFinalBlock && padding == PaddingPKCS7 {
			return Pkcs7Unpad(result, mc.blockSize)
		}
		return result, nil

	case ModeCFB:
		if padding != PaddingNON {
			return nil, errors.New("CFB mode does not support padding")
		}
		if mc.lastBlock == nil {
			if len(data) < mc.blockSize {
				return nil, errors.New("CFB Decrypt: ciphertext too short for IV")
			}
			mc.lastBlock = make([]byte, mc.blockSize)
			copy(mc.lastBlock, data[:mc.blockSize])
			return []byte{}, nil
		}
		keystream, err := mc.BlockCipherEncrypt(mc.lastBlock)
		if err != nil {
			return nil, err
		}
		n := len(data)
		if n < mc.blockSize {
			keystream = keystream[:n]
		}
		plaintext, err := xorBytes(data, keystream)
		if err != nil {
			return nil, err
		}
		if len(data) == mc.blockSize {
			mc.lastBlock = data
		}
		return plaintext, nil

	case ModeOFB:
		if padding != PaddingNON {
			return nil, errors.New("OFB mode does not support padding")
		}
		if mc.lastBlock == nil {
			if len(data) < mc.blockSize {
				return nil, errors.New("OFB Decrypt: ciphertext too short for IV")
			}
			mc.lastBlock = make([]byte, mc.blockSize)
			copy(mc.lastBlock, data[:mc.blockSize])
			return []byte{}, nil
		}
		keystream, err := mc.BlockCipherEncrypt(mc.lastBlock)
		if err != nil {
			return nil, err
		}
		n := len(data)
		if n < mc.blockSize {
			keystream = keystream[:n]
		}
		plaintext, err := xorBytes(data, keystream)
		if err != nil {
			return nil, err
		}
		mc.lastBlock = keystream
		return plaintext, nil

	case ModeCTR:
		if padding != PaddingNON {
			return nil, errors.New("CTR mode does not support padding")
		}
		if mc.lastBlock == nil {
			if len(data) < mc.blockSize {
				return nil, errors.New("CTR Decrypt: ciphertext too short for IV")
			}
			mc.lastBlock = make([]byte, mc.blockSize)
			copy(mc.lastBlock, data[:mc.blockSize])
			return []byte{}, nil
		}
		counter := make([]byte, mc.blockSize)
		copy(counter, mc.lastBlock)
		keystream, err := mc.BlockCipherEncrypt(counter)
		if err != nil {
			return nil, err
		}
		n := len(data)
		if n < mc.blockSize {
			keystream = keystream[:n]
		}
		decrypted, err := xorBytes(data, keystream)
		if err != nil {
			return nil, err
		}
		result = append(result, decrypted...)
		if isFinalBlock {
			incMsgCTR(counter)
		} else {
			incBlockCTR(counter)
		}
		mc.lastBlock = counter
		return result, nil

	default:
		return nil, fmt.Errorf("unsupported mode: %s", mc.mode)
	}
}

// --- Интерфейс Encrypt/Decrypt для всего сообщения ---
// Encrypt шифрует всё сообщение. Если iv == nil или пустой и режим требует IV,
// он генерируется автоматически и прикрепляется в начало результата.
// Если iv передан, он используется как начальное заполнение (mc.lastBlock).
func (mc *MyCipher) Encrypt(data []byte, iv []byte) ([]byte, error) {
	if mc.key == nil {
		return nil, errors.New("key unsetted")
	}
	var result []byte
	var padding string
	if mc.mode == ModeECB || mc.mode == ModeCBC {
		padding = PaddingPKCS7
	} else {
		padding = PaddingNON
	}

	if mc.requiresIV() {
		if iv != nil && len(iv) == mc.blockSize {
			mc.lastBlock = make([]byte, mc.blockSize)
			copy(mc.lastBlock, iv)
			result = append(result, iv...)
		} else {
			if mc.mode == ModeCTR {
				if mc.nonce == nil {
					nonce := make([]byte, NonceSize)
					if n, err := rand.Read(nonce); err != nil || n != NonceSize {
						return nil, errors.New("failed to generate nonce")
					}
					mc.nonce = nonce
				}
				newIV := make([]byte, IVSize)
				if n, err := rand.Read(newIV); err != nil || n != IVSize {
					return nil, errors.New("failed to generate IV for CTR")
				}
				counterBlock := make([]byte, CounterSize) // zeros
				ctr := append(append(append([]byte{}, mc.nonce...), newIV...), counterBlock...)
				if len(ctr) != mc.blockSize {
					return nil, fmt.Errorf("CTR: invalid ctr length, got %d, expected %d", len(ctr), mc.blockSize)
				}
				mc.lastBlock = ctr
				result = append(result, ctr...)
			} else {
				// Для CBC, CFB, OFB: генерируем случайный IV размером blockSize.
				newIV := make([]byte, mc.blockSize)
				if n, err := rand.Read(newIV); err != nil || n != mc.blockSize {
					return nil, errors.New("failed to generate IV")
				}
				mc.lastBlock = newIV
				result = append(result, newIV...)
			}
		}
	} else {
		mc.lastBlock = nil
	}

	for len(data) > mc.blockSize {
		block := data[:mc.blockSize]
		encBlock, err := mc.ProcessBlockEncrypt(block, false, padding)
		if err != nil {
			return nil, err
		}
		result = append(result, encBlock...)
		data = data[mc.blockSize:]
	}
	// Шифруем последний блок
	encBlock, err := mc.ProcessBlockEncrypt(data, true, padding)
	if err != nil {
		return nil, err
	}
	result = append(result, encBlock...)
	return result, nil
}

// Decrypt дешифрует всё сообщение. Если iv не передан, то в режиме с IV первый блок считается вектором инициализации.
func (mc *MyCipher) Decrypt(data []byte, iv []byte) ([]byte, error) {
	if mc.key == nil {
		return nil, errors.New("key unsetted")
	}
	if mc.requiresIV() {
		if iv != nil && len(iv) == mc.blockSize {
			mc.lastBlock = make([]byte, mc.blockSize)
			copy(mc.lastBlock, iv)
		} else {
			if len(data) < mc.blockSize {
				return nil, errors.New("data too short to contain IV")
			}
			mc.lastBlock = make([]byte, mc.blockSize)
			copy(mc.lastBlock, data[:mc.blockSize])
			data = data[mc.blockSize:]
		}
	} else {
		mc.lastBlock = nil
	}
	var result []byte
	var padding string
	if mc.mode == ModeECB || mc.mode == ModeCBC {
		padding = PaddingPKCS7
	} else {
		padding = PaddingNON
	}
	for len(data) > mc.blockSize {
		block := data[:mc.blockSize]
		decBlock, err := mc.ProcessBlockDecrypt(block, false, padding)
		if err != nil {
			return nil, err
		}
		result = append(result, decBlock...)
		data = data[mc.blockSize:]
	}
	// Расшифруем последний блок
	decBlock, err := mc.ProcessBlockDecrypt(data, true, padding)
	if err != nil {
		return nil, err
	}
	result = append(result, decBlock...)
	return result, nil
}
