# IDA Assistant

IDA Assistant is an IDA Pro plugin that leverages Anthropic's Claude-3-7 model to assist users in reverse engineering and binary analysis tasks. This project is a fork of [stuxnet147/IDA-Assistant](https://github.com/stuxnet147/IDA-Assistant), enhanced with the latest Claude-3-7-sonnet model and various performance improvements.

[한국어 README](README_KR.md)

## Key Features

- **Claude-3-7-sonnet Model Support**: Utilizes the latest Claude-3-7-sonnet model for more accurate and useful analysis results
- **Improved System Prompt**: 
  - Enhanced prompt structure with clear sections and better organization
  - Optimized command usage instructions to prevent common errors
  - Improved response format guidelines for better AI outputs
- **Secure API Key Management**:
  - One-time API key input with encrypted storage
  - Machine-specific encryption for additional security
  - API key is only decrypted in memory when the plugin is active
- **Token Management System**: 
  - Automatic token counting and message length management
  - Automatic removal of older messages when prompt length exceeds limits
- **Conversation Control**: 
  - UI for stopping analysis at any time during the conversation
  - Explicit conversation termination by AI using the end_conversation command
  - Visual feedback when conversation is stopped
  - Distinct termination commands for successful completion and failure scenarios
  - Clear visual indication of analysis success or failure
- **Enhanced Function Name Search**: Similarity-based function name matching and suggestions using the fuzzywuzzy library
- **Strengthened Error Handling**: 
  - Automatic retry mechanism for API rate limit errors
  - Improved error handling for various exception scenarios
- **IDA Pro Integration**: 
  - Disassembly retrieval
  - Function decompilation
  - Address renaming
  - Function start/end address retrieval
  - Address lookup by name
  - Cross-reference analysis (xrefs)
  - Adding comments to addresses

## Installation

### Clone the repository:
```sh
git clone https://github.com/MeroZemory/IDA-Assistant.git
```

### Install dependencies:
```sh
pip install anthropic fuzzywuzzy
```

### Configuration:
1. Copy the `IDA_Assistant.py` file to your IDA Pro plugins directory.
2. Launch IDA Pro and enable the "IDA Assistant" plugin from the "Edit" menu.
3. When prompted, enter your Anthropic API key. The key will be encrypted and securely stored for future use.

## Usage

1. Press Alt+F1 or go to "Edit" > "Plugins" > "IDA Assistant" to open the assistant window.
2. If this is your first time using the plugin, you'll be prompted to enter your Anthropic API key.
3. Type your query or request in the input field and click "Send" or press Enter.
4. The AI assistant will analyze your query, execute relevant commands, and provide helpful suggestions and information.
5. To stop the analysis during conversation, click the "Stop" button.
6. To update your API key at any time, click the "Set API Key" button in the assistant window.
7. Review the assistant's response in the chat history and follow the provided guidance to aid your reverse engineering process.
8. Continue the conversation with the assistant as needed, refining your queries and exploring different aspects of binary analysis.

## Recent Updates

- **March 2025**: 
  - Added secure API key management with encryption
  - Restructured system prompt for better organization and clarity
  - Improved command documentation and usage instructions
  - Enhanced response format guidelines for more useful AI outputs
  - Implemented distinct conversation termination commands for success and failure scenarios
- Updated to Claude-3-7-sonnet-latest model for improved analysis performance
- Added token counting and automatic message length management
- Implemented conversation interruption feature (Stop button)
- Enhanced function name search using the fuzzywuzzy library
- Strengthened retry mechanism and error handling logic

## Acknowledgments

- The system prompt used in this plugin was inspired by the AutoGPT project.
- The query functions were adapted from the Gepetto IDA Pro plugin.
- Original project: [stuxnet147/IDA-Assistant](https://github.com/stuxnet147/IDA-Assistant)

## License

This project is licensed under the MIT License.
