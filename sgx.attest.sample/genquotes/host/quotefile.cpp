#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "quotefile.h"

QuoteFile::QuoteFile(oe_report_t parsedReport, uint8_t *quote, size_t quoteSize, uint8_t *ehd, size_t ehdSize)
: _parsedReport(parsedReport),
  _quote(quote),
  _quoteSize(quoteSize),
  _enclaveHeldData(ehd),
  _enclaveHeldDataSize(ehdSize)
{
}

void QuoteFile::WriteToJsonFile(const char *directory, const char* jsonFileName)
{
    struct stat st = {0};
    if (stat(directory, &st) == -1) {
        mkdir(directory, 0700);
    }

    char jsonFullFileName[1024];
    sprintf(jsonFullFileName, "%s/%s", directory, jsonFileName);

    FILE *fp = fopen(jsonFullFileName, "w");
    WriteToJsonFile(fp);
    fclose(fp);
}

void QuoteFile::WriteToJsonFile (FILE *fp)
{
    const int hexBufferSize = 1024*64;
    char hexBuffer[hexBufferSize];

    fprintf(fp, "%s\n", "{");
    fprintf(fp, "  \"Type\": %d,\n", (int) _parsedReport.type);
    fprintf(fp, "  \"MrEnclaveHex\": \"%s\",\n", FormatHexBuffer(hexBuffer, hexBufferSize, _parsedReport.identity.unique_id, OE_UNIQUE_ID_SIZE));
    fprintf(fp, "  \"MrSignerHex\": \"%s\",\n", FormatHexBuffer(hexBuffer, hexBufferSize, _parsedReport.identity.signer_id, OE_SIGNER_ID_SIZE));
    fprintf(fp, "  \"ProductIdHex\": \"%s\",\n", FormatHexBuffer(hexBuffer, hexBufferSize, _parsedReport.identity.product_id, OE_PRODUCT_ID_SIZE));
    fprintf(fp, "  \"SecurityVersion\": %u,\n", (int) _parsedReport.identity.security_version);
    fprintf(fp, "  \"Attributes\": %u,\n", (int) _parsedReport.identity.attributes);
    fprintf(fp, "  \"QuoteHex\": \"%s\",\n", FormatHexBuffer(hexBuffer, hexBufferSize, _quote, _quoteSize));
    fprintf(fp, "  \"EnclaveHeldDataHex\": \"%s\"\n", FormatHexBuffer(hexBuffer, hexBufferSize, _enclaveHeldData, _enclaveHeldDataSize));
    fprintf(fp, "%s\n", "}");
}

const char *QuoteFile::FormatHexBuffer (char *buffer, uint maxSize, uint8_t *data, size_t size)
{
    if (size * 2 >= maxSize)
        return "DEADBEEF";

    for (int i=0; i < size; i++)
    {
        sprintf(&buffer[i*2], "%02X", data[i]);
    }
    buffer[size*2+1] = '\0';
    return buffer;
}


