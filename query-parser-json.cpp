#include "query-parser-json.h"

#include <iostream>

class SaxQuery : public nlohmann::json::json_sax_t {
public:
    int parseError;
    std::vector <QueryParam> *params;

    explicit SaxQuery(std::vector <QueryParam> *aParams)
        : parseError(0), params(aParams)
    {
        QueryParam p;
        params->emplace_back();
    }

    bool null() override {
        return true;
    }

    bool boolean(bool val) override {
        params->back() = val;
        return true;
    }

    bool number_integer(number_integer_t val) override {
        params->back() = (long) val;
        return true;
    }

    bool number_unsigned(number_unsigned_t val) override {
        params->back() = (unsigned long) val;
        return true;
    }

    bool number_float(number_float_t val, const string_t &s) override {
        params->back() = val;
        return true;
    }

    bool string(string_t &val) override {
        params->back() = val;
        return true;
    }

    bool start_object(std::size_t elements) override {
        return true;
    }

    bool end_object() override {
        return true;
    }

    bool start_array(std::size_t elements) override {
        return true;
    }

    bool end_array() override {
        return true;
    }

    bool key(string_t &val) override {
        return true;
    }

    bool binary(nlohmann::json::binary_t &val) override {
        return true;
    }

    bool parse_error(std::size_t position, const std::string &last_token, const nlohmann::json::exception &ex) override {
        parseError = - ex.id;
        std::cerr << ex.what() << std::endl;
        return false;
    }
};

int QueryParserJson::parse(
    std::vector <QueryParam> *params,
    const char *json,
    size_t size
) {
    SaxQuery consumer(params);
    nlohmann::json::sax_parse(json, json + size, &consumer);
    return consumer.parseError;
}

int QueryParserJson::parse(
    std::vector <QueryParam> *params,
    const std::string &json
) {
    SaxQuery consumer(params);
    nlohmann::json::sax_parse(json, &consumer);
    return consumer.parseError;
}
