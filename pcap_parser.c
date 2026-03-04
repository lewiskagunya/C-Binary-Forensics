#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* --- 1. THE BINARY MAPS (STRUCTS) --- */

// The Global Header (24 bytes total)
typedef struct pcap_global_hdr_s {
    uint32_t magic_number;   // Identifies the file (0xa1b2c3d4)
    uint16_t version_major;  // Major version (usually 2)
    uint16_t version_minor;  // Minor version (usually 4)
    int32_t  thiszone;       // Timezone correction
    uint32_t sigfigs;        // Accuracy of timestamps
    uint32_t snaplen;        // Max length of captured packets
    uint32_t network;        // Data link type (Ethernet = 1)
} pcap_hdr_t;

// The Individual Packet Header (16 bytes total)
typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         // Timestamp: Seconds
    uint32_t ts_usec;        // Timestamp: Microseconds
    uint32_t incl_len;       // Bytes of packet saved in this file
    uint32_t orig_len;       // Actual length of packet on the wire
} pcaprec_hdr_t;

/* --- 2. THE MAIN ENGINE --- */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_file.pcap>\n", argv[0]);
        return 1;
    }

    // Open the source (binary read) and destination (text write)
    FILE *pcap_file = fopen(argv[1], "rb");
    FILE *csv_file = fopen("forensics_report.csv", "w");

    if (!pcap_file || !csv_file) {
        perror("Error opening files");
        return 1;
    }

    // Initialize the headers
    pcap_hdr_t global_header;
    pcaprec_hdr_t packet_header;
    int packet_count = 0;

    // STEP 1: Read Global Header (first 24 bytes)
    fread(&global_header, sizeof(pcap_hdr_t), 1, pcap_file);

    // Write CSV column headers
    fprintf(csv_file, "Packet_No, Epoch_Time, Micro_Sec, Captured_Size, Original_Size\n");

    // STEP 2: Loop through every packet in the file
    // fread returns 1 as long as it successfully reads a 16-byte packet header
    while (fread(&packet_header, sizeof(pcaprec_hdr_t), 1, pcap_file) == 1) {
        packet_count++;

        // Write packet metadata to our CSV report
        fprintf(csv_file, "%d, %u, %u, %u, %u\n", 
                packet_count, 
                packet_header.ts_sec, 
                packet_header.ts_usec, 
                packet_header.incl_len, 
                packet_header.orig_len);

        // STEP 3: THE JUMP (Erickson-style pointer manipulation)
        // We read the header, but now we must skip the actual packet data (incl_len)
        // to land exactly at the start of the next packet's header.
        fseek(pcap_file, packet_header.incl_len, SEEK_CUR);
    }

    printf("\n[+] Success: Processed %d packets.\n", packet_count);
    printf("[+] Forensic data saved to: forensics_report.csv\n");

    fclose(pcap_file);
    fclose(csv_file);
    return 0;
}
