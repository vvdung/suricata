/******************************
 * \author Vo Viet Dung <vvdung@husc.edu.vn>
 ******************************/
#ifndef __KDD_FEATURE_H__
#define __KDD_FEATURE_H__

void     _DumpHex(uint8_t* pAddress,int iSize);

/*Update global KDDFeatures of threadVars*/
void     KDD_IPOnlyInit(void* detectEngineCtx);

void     KDD_Init_PacketHandler(void* threadVars);
void     KDD_Initialization(void);
void     KDD_Update_Features(void* threadVars,void *de, void *det, void* packet);

#endif /* __KDD_FEATURE_H__ */