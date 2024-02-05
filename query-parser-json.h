#ifndef QUERYPARSERJSON_H
#define QUERYPARSERJSON_H

#include <vector>
#include "nlohmann/json.hpp"

enum QUERY_PARAM_TYPE {
    QUERY_PARAM_INT = 0,
    QUERY_PARAM_BOOL,
    QUERY_PARAM_FLOAT,
    QUERY_PARAM_STRING
};

class QueryParam {
public:
    QUERY_PARAM_TYPE t;
    long i;
    bool b;
    float f;
    std::string s;
    QueryParam()
        : t(QUERY_PARAM_INT), i(0), b(false), f(0.0)
    {

    }

    void operator=(bool val) {
        t = QUERY_PARAM_BOOL;
        b = val;
    }
    void operator=(long val) {
        t = QUERY_PARAM_INT;
        i = val;
    }
    void operator=(unsigned long val) {
        t = QUERY_PARAM_INT;
        i = val;
    }
    void operator=(float val) {
        t = QUERY_PARAM_FLOAT;
        f = val;
    }
    void operator=(double val) {
        t = QUERY_PARAM_FLOAT;
        f = val;
    }
    void operator=(const std::string &val) {
        t = QUERY_PARAM_STRING;
        s = val;
    }
};

/**
 * Parse function name and parameters into params vector
 */
class QueryParserJson {
public:
    /**
     * Parse JSON
     * @param params return value
     * @param json JSON string to parse
     *  1) array ["functionName", "param1"]
     *  2) object {"fn": "functionName", "param1": 1, "param2": 2.0]
     *  3) mixed {"f": "functionName", "p": ["param1", 2.0, 3]
     * @param size input buffer size
     * @return array of params, first element is function name
     */
    static int parse(
        std::vector <QueryParam> *params,
        const char *json,
        size_t size
    );
};

#endif
