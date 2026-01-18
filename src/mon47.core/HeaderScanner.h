#pragma once

#include "../../../sutra/Src/_SutraFramework/Struct.h"

class CScanner
{
public:
	CScanner(void);
	~CScanner(void);

	ECODE Scan(std::tstring strURL);
};
