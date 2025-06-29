unit Unit1;

//====================================================================================
// MORMOT V2 CRYPTOGRAPHY DEMONSTRATION UTILITY
//====================================================================================
// Author: BitmasterXor
// Purpose: Professional-grade encryption/decryption utility showcasing mORMot V2
//          cryptographic capabilities including AES encryption, hashing, HMAC,
//          PBKDF2 key derivation, and secure random number generation
//
// Features:
//   - Multiple AES encryption modes (ECB, CBC, CFB, OFB, CTR, GCM, CFC, OFC, CTC)
//   - Variable key sizes (128, 192, 256-bit)
//   - Multiple hash algorithms (MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA-3)
//   - HMAC-SHA256 message authentication
//   - PBKDF2 key derivation
//   - Cryptographically secure random number generation
//   - Base64 or Hexadecimal output encoding
//   - Performance metrics and detailed operation logging
//
// Security Notes:
//   - ECB mode is included for educational purposes only - NOT RECOMMENDED for production
//   - AEAD modes (GCM, CFC, OFC, CTC) provide both encryption and authentication
//   - Random IV usage is strongly recommended for all encryption operations
//   - PBKDF2 with high iteration count protects against rainbow table attacks
//
// Dependencies: mORMot V2 Framework
//====================================================================================

interface

uses
  // Windows API and VCL Components
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls,
  Vcl.ExtCtrls, Vcl.Grids, Vcl.ValEdit,

  // mORMot V2 Cryptographic Framework
  mormot.crypt.core,    // Core cryptographic functions and types
  mormot.crypt.secure,  // Secure random number generation and key derivation
  mormot.core.base,     // Base utility functions and types
  mormot.core.text,     // Text processing and encoding functions
  mormot.core.buffers;  // Buffer management and manipulation

//====================================================================================
// ENUMERATION TYPES
//====================================================================================

/// <summary>
/// Defines the available AES encryption modes supported by this application
/// </summary>
/// <remarks>
/// ECB: Electronic Codebook - Simplest but least secure (deterministic)
/// CBC: Cipher Block Chaining - Most common, requires padding
/// CFB: Cipher Feedback - Stream cipher mode, no padding needed
/// OFB: Output Feedback - Stream cipher mode, no padding needed
/// CTR: Counter Mode - Fast, parallelizable stream cipher
/// GCM: Galois/Counter Mode - AEAD mode with built-in authentication
/// CFC: mORMot CFB + CRC32C - Custom AEAD with integrity verification
/// OFC: mORMot OFB + CRC32C - Custom AEAD with integrity verification
/// CTC: mORMot CTR + CRC32C - Custom AEAD with integrity verification
/// </remarks>
type
  TEncryptionMode = (
    emAES_ECB,      // Electronic Codebook (NOT RECOMMENDED for production)
    emAES_CBC,      // Cipher Block Chaining
    emAES_CFB,      // Cipher Feedback
    emAES_OFB,      // Output Feedback
    emAES_CTR,      // Counter Mode
    emAES_GCM,      // Galois/Counter Mode (AEAD)
    emAES_CFC,      // CFB + CRC32C (mORMot custom AEAD)
    emAES_OFC,      // OFB + CRC32C (mORMot custom AEAD)
    emAES_CTC       // CTR + CRC32C (mORMot custom AEAD)
  );

/// <summary>
/// Defines the supported AES key sizes in bits
/// </summary>
/// <remarks>
/// Larger key sizes provide stronger security but slightly impact performance
/// 256-bit keys are recommended for high-security applications
/// </remarks>
  TKeySize = (
    ks128,          // 128-bit key (16 bytes) - Fast, good security
    ks192,          // 192-bit key (24 bytes) - Enhanced security
    ks256           // 256-bit key (32 bytes) - Maximum security
  );

//====================================================================================
// MAIN FORM CLASS DECLARATION
//====================================================================================

/// <summary>
/// Main application form providing comprehensive cryptographic operations interface
/// </summary>
/// <remarks>
/// This form demonstrates professional usage of mORMot V2 cryptographic functions
/// including encryption/decryption, hashing, message authentication, and key derivation
/// </remarks>
  TForm1 = class(TForm)
    //==================================================================================
    // VISUAL COMPONENTS - TAB CONTROL AND PAGES
    //==================================================================================
    PageControl1: TPageControl;           // Main tab container
    TabSheet1: TTabSheet;                 // Encryption/Decryption tab
    TabSheet2: TTabSheet;                 // Hash functions tab
    TabSheet3: TTabSheet;                 // HMAC and PBKDF2 tab
    TabSheet4: TTabSheet;                 // Random number generation tab

    //==================================================================================
    // ENCRYPTION/DECRYPTION INTERFACE COMPONENTS
    //==================================================================================
    GroupBox1: TGroupBox;                 // Encryption settings group
    Label1: TLabel;                       // Mode selection label
    Label2: TLabel;                       // Key size selection label
    Label3: TLabel;                       // Password input label
    Label14: TLabel;                      // Additional settings label
    ComboBoxMode: TComboBox;              // Encryption mode selector
    ComboBoxKeySize: TComboBox;           // Key size selector
    EditPassword: TEdit;                  // Password/passphrase input
    CheckBoxUseRandomIV: TCheckBox;       // Random IV option
    CheckBoxBase64Output: TCheckBox;      // Output encoding option

    GroupBox2: TGroupBox;                 // Input data group
    Label4: TLabel;                       // Input data label
    MemoInput: TMemo;                     // Plain text input area

    GroupBox3: TGroupBox;                 // Output data group
    Label5: TLabel;                       // Output data label
    MemoOutput: TMemo;                    // Encrypted/decrypted output area

    GroupBox4: TGroupBox;                 // Operation information group
    ValueListEditorInfo: TValueListEditor; // Detailed operation metrics

    // Operation buttons
    ButtonEncrypt: TButton;               // Encrypt operation trigger
    ButtonDecrypt: TButton;               // Decrypt operation trigger
    ButtonClear: TButton;                 // Clear all fields

    //==================================================================================
    // HASH FUNCTIONS INTERFACE COMPONENTS
    //==================================================================================
    GroupBox5: TGroupBox;                 // Hash calculation group
    Label6: TLabel;                       // Hash input label
    Label7: TLabel;                       // Hash algorithm label
    EditHashInput: TEdit;                 // Text to be hashed
    ComboBoxHashType: TComboBox;          // Hash algorithm selector
    EditHashOutput: TEdit;                // Hash result display
    ButtonHash: TButton;                  // Hash calculation trigger

    //==================================================================================
    // HMAC (MESSAGE AUTHENTICATION) INTERFACE COMPONENTS
    //==================================================================================
    GroupBox6: TGroupBox;                 // HMAC group
    Label8: TLabel;                       // HMAC key label
    Label9: TLabel;                       // HMAC input label
    EditHMACKey: TEdit;                   // HMAC secret key
    EditHMACInput: TEdit;                 // Message to authenticate
    EditHMACOutput: TEdit;                // HMAC result
    ButtonHMAC: TButton;                  // HMAC calculation trigger

    //==================================================================================
    // PBKDF2 (KEY DERIVATION) INTERFACE COMPONENTS
    //==================================================================================
    GroupBox7: TGroupBox;                 // PBKDF2 group
    Label10: TLabel;                      // Password label
    Label11: TLabel;                      // Salt label
    Label12: TLabel;                      // Iterations label
    EditPBKDF2Password: TEdit;            // Source password
    EditPBKDF2Salt: TEdit;                // Cryptographic salt
    EditPBKDF2Iterations: TEdit;          // Iteration count
    EditPBKDF2Output: TEdit;              // Derived key output
    ButtonPBKDF2: TButton;                // Key derivation trigger

    //==================================================================================
    // RANDOM NUMBER GENERATION INTERFACE COMPONENTS
    //==================================================================================
    GroupBox8: TGroupBox;                 // Random generation group
    Label13: TLabel;                      // Length specification label
    MemoRandomBytes: TMemo;               // Random data display
    EditRandomLength: TEdit;              // Desired byte count
    ButtonGenerateRandom: TButton;        // Random generation trigger

    //==================================================================================
    // EVENT HANDLERS
    //==================================================================================
    procedure FormCreate(Sender: TObject);
    procedure ButtonEncryptClick(Sender: TObject);
    procedure ButtonDecryptClick(Sender: TObject);
    procedure ButtonClearClick(Sender: TObject);
    procedure ComboBoxModeChange(Sender: TObject);
    procedure ButtonHashClick(Sender: TObject);
    procedure ButtonHMACClick(Sender: TObject);
    procedure ButtonPBKDF2Click(Sender: TObject);
    procedure ButtonGenerateRandomClick(Sender: TObject);

  private
    //==================================================================================
    // PRIVATE HELPER METHODS
    //==================================================================================

    /// <summary>Updates the information display with current encryption settings</summary>
    procedure UpdateInfo;

    /// <summary>Adds a key-value pair to the information display</summary>
    /// <param name="Key">Information category name</param>
    /// <param name="Value">Corresponding value or description</param>
    procedure LogInfo(const Key, Value: string);

    /// <summary>Returns the currently selected encryption mode</summary>
    /// <returns>TEncryptionMode enumeration value</returns>
    function GetSelectedMode: TEncryptionMode;

    /// <summary>Returns the currently selected key size</summary>
    /// <returns>TKeySize enumeration value</returns>
    function GetSelectedKeySize: TKeySize;

    /// <summary>Converts the selected key size to bits</summary>
    /// <returns>Key size in bits (128, 192, or 256)</returns>
    function GetKeySizeInBits: Integer;

    /// <summary>Creates and configures an AES instance based on current settings</summary>
    /// <returns>Configured TAesAbstract instance or nil on failure</returns>
    /// <remarks>
    /// This method handles key derivation using PBKDF2 and creates the appropriate
    /// AES implementation based on the selected mode and key size
    /// </remarks>
    function CreateAESInstance: TAesAbstract;

    /// <summary>Displays an error message to the user</summary>
    /// <param name="Msg">Error message text</param>
    procedure ShowError(const Msg: string);

    /// <summary>Displays a success message to the user</summary>
    /// <param name="Msg">Success message text</param>
    procedure ShowSuccess(const Msg: string);

  public
    { Public declarations - None required for this implementation }
  end;

//====================================================================================
// GLOBAL VARIABLES
//====================================================================================

var
  Form1: TForm1;

implementation

{$R *.dfm}

//====================================================================================
// INFORMATION DISPLAY AND LOGGING METHODS
//====================================================================================

/// <summary>
/// Updates the information panel with current encryption configuration details
/// </summary>
/// <remarks>
/// Provides comprehensive information about the selected encryption mode,
/// key size, security features, and operational parameters to help users
/// understand the cryptographic choices they are making
/// </remarks>
procedure TForm1.UpdateInfo;
var
  ModeInfo: string;
begin
  // Clear existing information
  ValueListEditorInfo.Strings.Clear;

  // Generate detailed mode description based on selection
  case GetSelectedMode of
    emAES_ECB: ModeInfo := 'Electronic Codebook - Each block encrypted independently. NOT SECURE for multiple blocks!';
    emAES_CBC: ModeInfo := 'Cipher Block Chaining - Each block XORed with previous ciphertext. Requires padding.';
    emAES_CFB: ModeInfo := 'Cipher Feedback - Stream cipher mode. No padding required.';
    emAES_OFB: ModeInfo := 'Output Feedback - Stream cipher mode. No padding required.';
    emAES_CTR: ModeInfo := 'Counter Mode - Fast, parallelizable stream cipher. No padding required.';
    emAES_GCM: ModeInfo := 'Galois/Counter Mode - AEAD mode with built-in authentication.';
    emAES_CFC: ModeInfo := 'mORMot CFB + CRC32C - Custom AEAD with integrity check.';
    emAES_OFC: ModeInfo := 'mORMot OFB + CRC32C - Custom AEAD with integrity check.';
    emAES_CTC: ModeInfo := 'mORMot CTR + CRC32C - Custom AEAD with integrity check.';
  else
    ModeInfo := 'Unknown mode';
  end;

  // Log current configuration parameters
  LogInfo('Encryption Mode', ComboBoxMode.Text);
  LogInfo('Key Size', ComboBoxKeySize.Text);
  LogInfo('Mode Description', ModeInfo);
  LogInfo('Random IV', BoolToStr(CheckBoxUseRandomIV.Checked, True));
  LogInfo('Base64 Output', BoolToStr(CheckBoxBase64Output.Checked, True));

  // Indicate whether the mode provides authenticated encryption
  if GetSelectedMode in [emAES_GCM, emAES_CFC, emAES_OFC, emAES_CTC] then
    LogInfo('AEAD Mode', 'Yes - Provides Authentication + Encryption')
  else
    LogInfo('AEAD Mode', 'No - Encryption only');
end;

/// <summary>
/// Adds a key-value information pair to the display panel
/// </summary>
/// <param name="Key">The information category or parameter name</param>
/// <param name="Value">The corresponding value or description</param>
procedure TForm1.LogInfo(const Key, Value: string);
begin
  ValueListEditorInfo.Values[Key] := Value;
end;

//====================================================================================
// USER INTERFACE EVENT HANDLERS
//====================================================================================

/// <summary>
/// Handles encryption mode selection changes and updates information display
/// </summary>
procedure TForm1.ComboBoxModeChange(Sender: TObject);
begin
  UpdateInfo;
end;

/// <summary>
/// Displays formatted error messages to the user
/// </summary>
/// <param name="Msg">The error message to display</param>
procedure TForm1.ShowError(const Msg: string);
begin
  MessageDlg('Error: ' + Msg, mtError, [mbOK], 0);
end;

/// <summary>
/// Displays formatted success messages to the user
/// </summary>
/// <param name="Msg">The success message to display</param>
procedure TForm1.ShowSuccess(const Msg: string);
begin
  MessageDlg('Success: ' + Msg, mtInformation, [mbOK], 0);
end;

//====================================================================================
// CORE ENCRYPTION FUNCTIONALITY
//====================================================================================

/// <summary>
/// Handles the encryption operation with comprehensive error handling and metrics
/// </summary>
/// <remarks>
/// This method performs the following operations:
/// 1. Validates input parameters (text and password)
/// 2. Creates appropriate AES instance based on current settings
/// 3. Encrypts the input text using PKCS7 padding
/// 4. Encodes output as Base64 or Hexadecimal based on user preference
/// 5. Calculates and displays performance metrics
/// 6. Properly cleans up cryptographic objects
/// </remarks>
procedure TForm1.ButtonEncryptClick(Sender: TObject);
var
  AES: TAesAbstract;           // AES encryption instance
  PlainText: RawByteString;    // Input data as UTF-8 bytes
  CipherText: RawByteString;   // Encrypted output bytes
  Output: string;              // Formatted output string
  StartTime: TDateTime;        // Performance measurement start
  ElapsedMs: Double;           // Elapsed time in milliseconds
begin
  // Validate input data presence
  if Trim(MemoInput.Text) = '' then
  begin
    ShowError('Please enter text to encrypt');
    Exit;
  end;

  // Validate password/passphrase presence
  if Trim(EditPassword.Text) = '' then
  begin
    ShowError('Please enter a password');
    Exit;
  end;

  AES := nil;
  try
    // Begin performance measurement
    StartTime := Now;

    // Create and configure AES instance
    AES := CreateAESInstance;
    if AES = nil then
    begin
      ShowError('Failed to create AES instance');
      Exit;
    end;

    // Convert input text to UTF-8 byte representation
    PlainText := ToUtf8(MemoInput.Text);

    // Perform encryption with PKCS7 padding and optional random IV
    // The CheckBoxUseRandomIV.Checked parameter determines whether to use
    // a cryptographically secure random IV (recommended) or a zero IV
    CipherText := AES.EncryptPkcs7(PlainText, CheckBoxUseRandomIV.Checked);

    // Calculate elapsed time for performance metrics
    ElapsedMs := (Now - StartTime) * 24 * 60 * 60 * 1000;

    // Format output according to user preference
    if CheckBoxBase64Output.Checked then
      Output := BinToBase64(CipherText)    // Base64 encoding (more compact)
    else
      Output := BinToHex(CipherText);      // Hexadecimal encoding (more readable)

    // Display encrypted result
    MemoOutput.Text := Output;

    // Log comprehensive operation metrics
    LogInfo('Operation', 'Encryption');
    LogInfo('Input Length', IntToStr(Length(PlainText)) + ' bytes');
    LogInfo('Output Length', IntToStr(Length(CipherText)) + ' bytes');
    LogInfo('Encryption Time', FormatFloat('0.000', ElapsedMs) + ' ms');
    LogInfo('Throughput', FormatFloat('0.00', Length(PlainText) / (ElapsedMs / 1000) / 1024) + ' KB/s');

    ShowSuccess('Text encrypted successfully');

  except
    on E: Exception do
      ShowError('Encryption failed: ' + E.Message);
  end;

  // Ensure proper cleanup of cryptographic objects
  if Assigned(AES) then
    AES.Free;
end;

/// <summary>
/// Handles the decryption operation with comprehensive error handling and metrics
/// </summary>
/// <remarks>
/// This method performs the following operations:
/// 1. Validates encrypted data and password presence
/// 2. Creates appropriate AES instance matching encryption settings
/// 3. Converts encoded input back to binary format
/// 4. Decrypts the data using PKCS7 padding removal
/// 5. Converts result back to readable text format
/// 6. Calculates and displays performance metrics
/// 7. Properly cleans up cryptographic objects
/// </remarks>
procedure TForm1.ButtonDecryptClick(Sender: TObject);
var
  AES: TAesAbstract;           // AES decryption instance
  CipherText: RawByteString;   // Encrypted input bytes
  PlainText: RawByteString;    // Decrypted output bytes
  Output: string;              // Formatted output string
  StartTime: TDateTime;        // Performance measurement start
  ElapsedMs: Double;           // Elapsed time in milliseconds
begin
  // Validate encrypted data presence
  if Trim(MemoOutput.Text) = '' then
  begin
    ShowError('No encrypted data to decrypt');
    Exit;
  end;

  // Validate password presence
  if Trim(EditPassword.Text) = '' then
  begin
    ShowError('Please enter the password');
    Exit;
  end;

  AES := nil;
  try
    // Begin performance measurement
    StartTime := Now;

    // Create AES instance with identical settings used for encryption
    AES := CreateAESInstance;
    if AES = nil then
    begin
      ShowError('Failed to create AES instance');
      Exit;
    end;

    // Convert encoded input back to binary format
    // Must match the encoding method used during encryption
    if CheckBoxBase64Output.Checked then
      CipherText := Base64ToBin(MemoOutput.Text)  // Decode Base64
    else
      CipherText := HexToBin(MemoOutput.Text);    // Decode Hexadecimal

    // Perform decryption with PKCS7 padding removal
    // The random IV parameter must match the encryption settings
    PlainText := AES.DecryptPkcs7(CipherText, CheckBoxUseRandomIV.Checked);

    // Calculate elapsed time for performance metrics
    ElapsedMs := (Now - StartTime) * 24 * 60 * 60 * 1000;

    // Convert decrypted bytes back to readable text
    Output := Utf8ToString(PlainText);
    MemoInput.Text := Output;

    // Log comprehensive operation metrics
    LogInfo('Operation', 'Decryption');
    LogInfo('Input Length', IntToStr(Length(CipherText)) + ' bytes');
    LogInfo('Output Length', IntToStr(Length(PlainText)) + ' bytes');
    LogInfo('Decryption Time', FormatFloat('0.000', ElapsedMs) + ' ms');
    LogInfo('Throughput', FormatFloat('0.00', Length(PlainText) / (ElapsedMs / 1000) / 1024) + ' KB/s');

    ShowSuccess('Text decrypted successfully');

  except
    on E: Exception do
      ShowError('Decryption failed: ' + E.Message);
  end;

  // Ensure proper cleanup of cryptographic objects
  if Assigned(AES) then
    AES.Free;
end;

/// <summary>
/// Clears all input/output fields and resets the information display
/// </summary>
procedure TForm1.ButtonClearClick(Sender: TObject);
begin
  MemoInput.Clear;
  MemoOutput.Clear;
  ValueListEditorInfo.Strings.Clear;
  UpdateInfo;
end;

//====================================================================================
// CRYPTOGRAPHIC HASH FUNCTIONS
//====================================================================================

/// <summary>
/// Handles hash calculation for various algorithms with proper error handling
/// </summary>
/// <remarks>
/// Supports multiple hash algorithms:
/// - MD5: 128-bit hash (deprecated for security applications)
/// - SHA-1: 160-bit hash (deprecated for security applications)
/// - SHA-256: 256-bit hash (recommended)
/// - SHA-384: 384-bit hash (high security)
/// - SHA-512: 512-bit hash (high security)
/// - SHA-3-256: 256-bit SHA-3 (latest standard)
/// - SHA-3-512: 512-bit SHA-3 (latest standard)
///
/// All hashes are output in hexadecimal format for readability
/// </remarks>
procedure TForm1.ButtonHashClick(Sender: TObject);
var
  Input: RawByteString;        // Input data as UTF-8 bytes
  Hash: RawByteString;         // Computed hash as hex string
  HashType: string;            // Selected hash algorithm name
  SHA3Hash: THash256;          // SHA-3 hash storage (256-bit)
begin
  // Validate input data presence
  if Trim(EditHashInput.Text) = '' then
  begin
    ShowError('Please enter text to hash');
    Exit;
  end;

  // Convert input to UTF-8 byte representation
  Input := ToUtf8(EditHashInput.Text);
  HashType := ComboBoxHashType.Text;

  try
    // Calculate hash based on selected algorithm
    case ComboBoxHashType.ItemIndex of
      0: begin
           // MD5 Hash Calculation (128-bit)
           // Note: MD5 is cryptographically broken - use only for checksums
           var MD5Hash: TMd5Digest;
           MD5Hash := Md5Buf(pointer(Input)^, Length(Input));
           Hash := BinToHex(@MD5Hash, SizeOf(MD5Hash));
         end;

      1: begin
           // SHA-1 Hash Calculation (160-bit)
           // Note: SHA-1 is deprecated for security applications
           var SHA1: TSha1;
           var SHA1Hash: TSha1Digest;
           SHA1.Full(pointer(Input), Length(Input), SHA1Hash);
           Hash := BinToHex(@SHA1Hash, SizeOf(SHA1Hash));
         end;

      2: begin
           // SHA-256 Hash Calculation (256-bit) - Recommended
           var SHA256Hash: TSha256Digest;
           SHA256Hash := Sha256Digest(pointer(Input), Length(Input));
           Hash := BinToHex(@SHA256Hash, SizeOf(SHA256Hash));
         end;

      3: begin
           // SHA-384 Hash Calculation (384-bit) - High Security
           var SHA: TSha384;
           var SHA384Hash: TSha384Digest;
           SHA.Full(pointer(Input), Length(Input), SHA384Hash);
           Hash := BinToHex(@SHA384Hash, SizeOf(SHA384Hash));
         end;

      4: begin
           // SHA-512 Hash Calculation (512-bit) - High Security
           var SHA: TSha512;
           var SHA512Hash: TSha512Digest;
           SHA.Full(pointer(Input), Length(Input), SHA512Hash);
           Hash := BinToHex(@SHA512Hash, SizeOf(SHA512Hash));
         end;

      5: begin
           // SHA-3-256 Hash Calculation (256-bit) - Latest Standard
           var SHA3: TSha3;
           SHA3.Full(SHA3_256, pointer(Input), Length(Input), @SHA3Hash, 256);
           Hash := BinToHex(@SHA3Hash, SizeOf(SHA3Hash));
         end;

      6: begin
           // SHA-3-512 Hash Calculation (512-bit) - Latest Standard
           var SHA3: TSha3;
           var SHA3Hash512: THash512;
           SHA3.Full(SHA3_512, pointer(Input), Length(Input), @SHA3Hash512, 512);
           Hash := BinToHex(@SHA3Hash512, SizeOf(SHA3Hash512));
         end;

    else
      // Default to SHA-256 if invalid selection
      begin
        var SHA256Hash: TSha256Digest;
        SHA256Hash := Sha256Digest(pointer(Input), Length(Input));
        Hash := BinToHex(@SHA256Hash, SizeOf(SHA256Hash));
      end;
    end;

    // Display computed hash result
    EditHashOutput.Text := Hash;
    ShowSuccess(HashType + ' hash calculated successfully');

  except
    on E: Exception do
      ShowError('Hashing failed: ' + E.Message);
  end;
end;

//====================================================================================
// MESSAGE AUTHENTICATION CODE (HMAC) FUNCTIONS
//====================================================================================

/// <summary>
/// Calculates HMAC-SHA256 for message authentication
/// </summary>
/// <remarks>
/// HMAC (Hash-based Message Authentication Code) provides both data integrity
/// and authenticity verification. It combines a cryptographic hash function
/// with a secret key to produce an authentication tag.
///
/// HMAC-SHA256 is widely used and provides strong security guarantees:
/// - Prevents message tampering
/// - Verifies message authenticity
/// - Resistant to length extension attacks
/// - Computationally secure with proper key management
/// </remarks>
procedure TForm1.ButtonHMACClick(Sender: TObject);
var
  Key: RawByteString;          // HMAC secret key
  Input: RawByteString;        // Message to authenticate
  HMAC: TSha256Digest;         // HMAC result (256-bit)
begin
  // Validate HMAC key presence
  if Trim(EditHMACKey.Text) = '' then
  begin
    ShowError('Please enter HMAC key');
    Exit;
  end;

  // Validate input message presence
  if Trim(EditHMACInput.Text) = '' then
  begin
    ShowError('Please enter text for HMAC');
    Exit;
  end;

  // Convert inputs to UTF-8 byte representation
  Key := ToUtf8(EditHMACKey.Text);
  Input := ToUtf8(EditHMACInput.Text);

  try
    // Calculate HMAC-SHA256
    // The key should be at least 32 bytes for optimal security
    // Shorter keys are automatically padded, longer keys are hashed
    HmacSha256(Key, Input, HMAC);

    // Display HMAC result in hexadecimal format
    EditHMACOutput.Text := BinToHex(@HMAC, SizeOf(HMAC));
    ShowSuccess('HMAC-SHA256 calculated successfully');

  except
    on E: Exception do
      ShowError('HMAC calculation failed: ' + E.Message);
  end;
end;

//====================================================================================
// KEY DERIVATION FUNCTIONS (PBKDF2)
//====================================================================================

/// <summary>
/// Performs PBKDF2 key derivation with comprehensive security measures
/// </summary>
/// <remarks>
/// PBKDF2 (Password-Based Key Derivation Function 2) strengthens passwords
/// against brute-force and rainbow table attacks through:
///
/// 1. Salt Addition: Prevents rainbow table attacks
/// 2. Iteration Count: Increases computational cost for attackers
/// 3. Standardized Algorithm: Uses HMAC-SHA256 internally
///
/// Security Recommendations:
/// - Use a unique random salt for each password
/// - Minimum 10,000 iterations (adjust based on security requirements)
/// - Higher iteration counts improve security but increase processing time
/// - Store salt and iteration count alongside the derived key
/// </remarks>
procedure TForm1.ButtonPBKDF2Click(Sender: TObject);
var
  Password: RawByteString;     // Source password
  Salt: RawByteString;         // Cryptographic salt
  Iterations: Integer;         // Iteration count for key strengthening
  Key: THash256;               // Derived key output (256-bit)
begin
  // Validate password presence
  if Trim(EditPBKDF2Password.Text) = '' then
  begin
    ShowError('Please enter password for PBKDF2');
    Exit;
  end;

  // Convert inputs to UTF-8 and parse iteration count
  Password := ToUtf8(EditPBKDF2Password.Text);
  Salt := ToUtf8(EditPBKDF2Salt.Text);
  Iterations := StrToIntDef(EditPBKDF2Iterations.Text, 10000);

  try
    // Perform PBKDF2 key derivation using HMAC-SHA256
    // Higher iteration counts provide better security but require more processing time
    // The salt should be unique and random for each password
    Pbkdf2HmacSha256(Password, Salt, Iterations, Key);

    // Display derived key in hexadecimal format
    EditPBKDF2Output.Text := BinToHex(@Key, SizeOf(Key));
    ShowSuccess('PBKDF2 key derived successfully');

  except
    on E: Exception do
      ShowError('PBKDF2 derivation failed: ' + E.Message);
  end;

  // Security: Clear sensitive key data from memory
  // This prevents key material from remaining in memory after use
  FillChar(Key, SizeOf(Key), 0);
end;

//====================================================================================
// CRYPTOGRAPHICALLY SECURE RANDOM NUMBER GENERATION
//====================================================================================

/// <summary>
/// Generates cryptographically secure random bytes using mORMot's PRNG
/// </summary>
/// <remarks>
/// Uses TAesPrng which provides cryptographically secure random number generation
/// suitable for:
/// - Cryptographic keys and initialization vectors
/// - Salts for password hashing
/// - Nonces for cryptographic protocols
/// - Session tokens and identifiers
///
/// The generated random data has high entropy and is suitable for security-critical
/// applications where predictable random numbers would compromise security.
/// </remarks>
procedure TForm1.ButtonGenerateRandomClick(Sender: TObject);
var
  Length: Integer;             // Requested number of random bytes
  RandomBytes: RawByteString;  // Generated random data
begin
  // Parse and validate requested length
  Length := StrToIntDef(EditRandomLength.Text, 32);
  if (Length < 1) or (Length > 1024) then
  begin
    ShowError('Length must be between 1 and 1024 bytes');
    Exit;
  end;

  try
    // Generate cryptographically secure random bytes
    // TAesPrng uses AES in counter mode seeded with OS entropy sources
    RandomBytes := TAesPrng.Fill(Length);

    // Display random data in hexadecimal format for readability
    MemoRandomBytes.Text := BinToHex(RandomBytes);
    ShowSuccess(IntToStr(Length) + ' random bytes generated');

  except
    on E: Exception do
      ShowError('Random generation failed: ' + E.Message);
  end;
end;

//====================================================================================
// FORM INITIALIZATION AND CONFIGURATION
//====================================================================================

/// <summary>
/// Initializes the form with default values and configures all UI components
/// </summary>
/// <remarks>
/// Sets up:
/// - Encryption mode options with security warnings
/// - Key size selections with bit specifications
/// - Hash algorithm options covering legacy and modern algorithms
/// - Reasonable default values for demonstration purposes
/// - Security-conscious defaults (256-bit keys, random IV, etc.)
/// </remarks>
procedure TForm1.FormCreate(Sender: TObject);
begin
  //================================================================================
  // ENCRYPTION MODE CONFIGURATION
  //================================================================================
  ComboBoxMode.Items.Clear;
  ComboBoxMode.Items.Add('AES-ECB (Electronic Codebook) - NOT RECOMMENDED');
  ComboBoxMode.Items.Add('AES-CBC (Cipher Block Chaining)');
  ComboBoxMode.Items.Add('AES-CFB (Cipher Feedback)');
  ComboBoxMode.Items.Add('AES-OFB (Output Feedback)');
  ComboBoxMode.Items.Add('AES-CTR (Counter Mode)');
  ComboBoxMode.Items.Add('AES-GCM (Galois/Counter Mode - AEAD)');
  ComboBoxMode.Items.Add('AES-CFC (CFB + CRC32C - mORMot AEAD)');
  ComboBoxMode.Items.Add('AES-OFC (OFB + CRC32C - mORMot AEAD)');
  ComboBoxMode.Items.Add('AES-CTC (CTR + CRC32C - mORMot AEAD)');
  ComboBoxMode.ItemIndex := 1; // Default to CBC (widely supported and secure)

  //================================================================================
  // KEY SIZE CONFIGURATION
  //================================================================================
  ComboBoxKeySize.Items.Clear;
  ComboBoxKeySize.Items.Add('128-bit');
  ComboBoxKeySize.Items.Add('192-bit');
  ComboBoxKeySize.Items.Add('256-bit');
  ComboBoxKeySize.ItemIndex := 2; // Default to 256-bit (maximum security)

  //================================================================================
  // HASH ALGORITHM CONFIGURATION
  //================================================================================
  ComboBoxHashType.Items.Clear;
  ComboBoxHashType.Items.Add('MD5');        // Legacy - not recommended for security
  ComboBoxHashType.Items.Add('SHA-1');      // Legacy - deprecated for security
  ComboBoxHashType.Items.Add('SHA-256');    // Recommended standard
  ComboBoxHashType.Items.Add('SHA-384');    // High security variant
  ComboBoxHashType.Items.Add('SHA-512');    // High security variant
  ComboBoxHashType.Items.Add('SHA-3-256');  // Latest standard
  ComboBoxHashType.Items.Add('SHA-3-512');  // Latest standard, high security
  ComboBoxHashType.ItemIndex := 2; // Default to SHA-256 (widely recommended)

  //================================================================================
  // DEFAULT VALUES CONFIGURATION
  //================================================================================
  // Set demonstration password (users should use strong, unique passwords)
  EditPassword.Text := 'MySecretPassword123';

  // Set sample text for encryption demonstration
  MemoInput.Text := 'This is a test message for encryption demonstration using mORMot V2 cryptography library.';

  // Configure security-conscious defaults
  CheckBoxUseRandomIV.Checked := True;      // Always use random IV for security
  CheckBoxBase64Output.Checked := True;     // Base64 is more compact than hex

  // Set reasonable defaults for random generation and key derivation
  EditRandomLength.Text := '32';            // 32 bytes = 256 bits
  EditPBKDF2Iterations.Text := '10000';     // Minimum recommended iterations
  EditPBKDF2Salt.Text := 'mySalt123';       // Demo salt (use random in production)

  // Initialize information display with current settings
  UpdateInfo;
end;

//====================================================================================
// CONFIGURATION HELPER METHODS
//====================================================================================

/// <summary>
/// Returns the currently selected encryption mode as an enumeration value
/// </summary>
/// <returns>TEncryptionMode corresponding to the user's selection</returns>
function TForm1.GetSelectedMode: TEncryptionMode;
begin
  Result := TEncryptionMode(ComboBoxMode.ItemIndex);
end;

/// <summary>
/// Returns the currently selected key size as an enumeration value
/// </summary>
/// <returns>TKeySize corresponding to the user's selection</returns>
function TForm1.GetSelectedKeySize: TKeySize;
begin
  Result := TKeySize(ComboBoxKeySize.ItemIndex);
end;

/// <summary>
/// Converts the selected key size enumeration to actual bit count
/// </summary>
/// <returns>Key size in bits (128, 192, or 256)</returns>
function TForm1.GetKeySizeInBits: Integer;
begin
  case GetSelectedKeySize of
    ks128: Result := 128;    // Fast encryption, good security
    ks192: Result := 192;    // Enhanced security
    ks256: Result := 256;    // Maximum security (recommended)
  else
    Result := 256;           // Default to maximum security
  end;
end;

//====================================================================================
// AES INSTANCE CREATION AND KEY DERIVATION
//====================================================================================

/// <summary>
/// Creates and configures an AES encryption instance based on current settings
/// </summary>
/// <returns>Configured TAesAbstract instance or nil on failure</returns>
/// <remarks>
/// This method performs the following critical operations:
///
/// 1. Key Derivation: Uses PBKDF2-HMAC-SHA256 to derive a strong encryption key
///    from the user's password and a fixed salt. In production applications,
///    use a unique random salt for each encryption operation.
///
/// 2. AES Mode Selection: Creates the appropriate AES implementation based on
///    the selected mode (ECB, CBC, CFB, OFB, CTR, GCM, CFC, OFC, CTC).
///
/// 3. Key Size Configuration: Supports 128, 192, and 256-bit keys with the
///    same derived key material (truncated or expanded as needed).
///
/// 4. Security Considerations:
///    - Uses a fixed salt for demonstration (use random salt in production)
///    - 1000 PBKDF2 iterations (increase for production use)
///    - Properly clears sensitive key material from memory
///
/// The caller is responsible for freeing the returned AES instance.
/// </remarks>
function TForm1.CreateAESInstance: TAesAbstract;
var
  Key: THash256;               // Derived encryption key (256-bit)
  KeyBits: Integer;            // Selected key size in bits
  Salt: RawByteString;         // Salt for key derivation
begin
  Result := nil;
  KeyBits := GetKeySizeInBits;

  // Use a fixed salt for demonstration purposes
  // SECURITY NOTE: In production applications, use a unique random salt
  // for each password/encryption operation and store it alongside the ciphertext
  Salt := 'mormot_demo_fixed_salt_2024';

  // Derive encryption key using PBKDF2-HMAC-SHA256
  // This strengthens the user's password against brute-force attacks
  // The iteration count (1000) is minimal - consider 10,000+ for production
  Pbkdf2HmacSha256(ToUtf8(EditPassword.Text), Salt, 1000, Key);

  // Create the appropriate AES implementation based on selected mode
  case GetSelectedMode of
    emAES_ECB: Result := TAesEcb.Create(Key, KeyBits); // NOT RECOMMENDED for production
    emAES_CBC: Result := TAesCbc.Create(Key, KeyBits); // Standard mode, requires padding
    emAES_CFB: Result := TAesCfb.Create(Key, KeyBits); // Stream mode, no padding
    emAES_OFB: Result := TAesOfb.Create(Key, KeyBits); // Stream mode, no padding
    emAES_CTR: Result := TAesCtr.Create(Key, KeyBits); // Fast, parallelizable
    emAES_GCM: Result := TAesGcm.Create(Key, KeyBits); // AEAD mode (authenticated)
    emAES_CFC: Result := TAesCfc.Create(Key, KeyBits); // mORMot AEAD variant
    emAES_OFC: Result := TAesOfc.Create(Key, KeyBits); // mORMot AEAD variant
    emAES_CTC: Result := TAesCtc.Create(Key, KeyBits); // mORMot AEAD variant
  end;

  // Security: Clear sensitive key material from memory immediately after use
  // This prevents key recovery through memory dumps or swap files
  FillChar(Key, SizeOf(Key), 0);
end;

end.
