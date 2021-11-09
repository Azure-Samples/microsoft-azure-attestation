#include <openenclave/host.h>

class QuoteFile
{
  private:
    oe_report_t _parsedReport;
    uint8_t* _enclaveHeldData;
    size_t _enclaveHeldDataSize;
    uint8_t* _quote;
    size_t _quoteSize;

  public:
    QuoteFile(oe_report_t parsedReport, uint8_t *quote, size_t quoteSize, uint8_t *ehd, size_t ehdSize);
    void WriteToJsonFile(const char *directory, const char* jsonFileName);
    void WriteToJsonFile(FILE *fp);

  private:
    const char *FormatHexBuffer (char *buffer, uint maxSize, uint8_t *data, size_t size);
};
