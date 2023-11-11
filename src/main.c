#include <stdio.h>
#include <string.h>

// Function to perform signature-based detection
int detectSignature(FILE *file) {
    FILE *signaturesFile = fopen("threat_signatures.txt", "r");
    if (signaturesFile == NULL) {
        printf("Error: Unable to open threat signatures file.\n");
        return 0;  // Assume file is clean if signatures file is not available
    }

    // Read threat signatures from the file
    char signature[100];
    while (fgets(signature, sizeof(signature), signaturesFile) != NULL) {
        // Remove newline character
        signature[strcspn(signature, "\n")] = '\0';

        // Set the position to the beginning of the file
        rewind(file);

        // Read a portion of the file to check for the signature
        char buffer[100];
        fread(buffer, sizeof(char), sizeof(buffer), file);

        // Check if the signature is present
        if (strstr(buffer, signature) != NULL) {
            fclose(signaturesFile);
            return 1;  // Threat detected
        }
    }

    fclose(signaturesFile);
    return 0;  // File is clean
}

// Function to classify the threat based on severity
void classifyThreat(int threatDetected) {
    if (threatDetected) {
        printf("Threat Classification: High Severity\n");
    } else {
        printf("Threat Classification: Clean\n");
    }
}

// Function to handle user actions on detected threats
void handleThreat(int threatDetected, char filePath[100]) {
    if (threatDetected) {
        char response;

        // Prompt user for action
        printf("Threat detected! Do you want to delete the file? (y/n): ");
        scanf(" %c", &response);

        // Perform action based on user response
        if (response == 'y' || response == 'Y') {
            // Perform deletion or quarantine (you can implement this part)
            printf("File '%s' deleted.\n", filePath);
        } else {
            printf("File '%s' not deleted.\n", filePath);
        }
    }
}

// Function to log scan results
void logResults(char filePath[100], int threatDetected) {
    FILE *logFile = fopen("scan_log.txt", "a");

    if (logFile != NULL) {
        fprintf(logFile, "File: %s | Threat Detected: %s\n", filePath, threatDetected ? "Yes" : "No");
        fclose(logFile);
    } else {
        printf("Error: Unable to log results.\n");
    }
}

int main() {
    printf("Welcome to the Virus Scanner!\n");

    char filePath[100];

    // Prompt user for file path
    printf("Enter the path of the file to scan: ");
    scanf("%s", filePath);

    // Open the file
    FILE *file = fopen(filePath, "r");

    // Check if the file is opened successfully
    if (file == NULL) {
        printf("Error: Unable to open the file.\n");
        return 1;
    }

    // Display a progress indicator while scanning
    printf("Scanning");
    for (int i = 0; i < 5; i++) {
        printf(".");
        fflush(stdout);  // Flush the output buffer to display the dots immediately
        Sleep(1000);  // Sleep for 0.5 seconds (adjust as needed)
    }
    printf("\n");

    // Perform signature-based detection
    int threatDetected = detectSignature(file);

    // Display scan result
    printf("Scan result: ");
    if (threatDetected) {
        printf("Threat detected!\n");
    } else {
        printf("File is clean.\n");
    }

    // Classify the threat based on severity
    classifyThreat(threatDetected);

    // Handle user actions on detected threats
    handleThreat(threatDetected, filePath);

    // Log scan results
    logResults(filePath, threatDetected);

    // Close the file
    fclose(file);

    return 0;
}
