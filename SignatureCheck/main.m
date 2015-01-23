//
//  main.cpp
//  SignatureCheckOSX
//
//  Created by Elviss Strazdins on 30.05.2014.
//  Copyright (c) 2014 Elviss. All rights reserved.
//
#import <Foundation/Foundation.h>
#include <TargetConditionals.h>
#include <mach-o/arch.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include <openssl/x509.h>
#include <openssl/pkcs7.h>

#if TARGET_OS_IPHONE
static const unsigned char PUBLIC_KEY[] = {};
#elif TARGET_OS_MAC
static const unsigned char PUBLIC_KEY[] = {0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc0, 0x3e, 0x43, 0xd4, 0x54, 0x51, 0x43, 0xe7, 0xc4, 0xd9, 0xd6, 0x07, 0xcb, 0x63, 0xcc, 0x4e, 0x8f, 0x77, 0x07, 0x65, 0x22, 0xaf, 0x3d, 0x79, 0xae, 0x3e, 0x9e, 0x0a, 0x72, 0x5d, 0x86, 0x99, 0x56, 0x23, 0xa5, 0xf9, 0xad, 0xf7, 0xb0, 0x9e, 0xf8, 0x1b, 0x53, 0x08, 0x3e, 0x22, 0x30, 0x66, 0x16, 0x2a, 0x90, 0xf1, 0x6d, 0x2d, 0x35, 0x6e, 0xea, 0x18, 0xa6, 0x36, 0x52, 0x3c, 0x11, 0x0a, 0x34, 0x9a, 0xe3, 0x53, 0x7b, 0x86, 0x9e, 0xa9, 0xc9, 0x18, 0x42, 0x31, 0x0d, 0xb6, 0xe7, 0x03, 0xb3, 0x77, 0x09, 0xc6, 0xff, 0x73, 0x59, 0xa4, 0xdf, 0xbe, 0x3e, 0x89, 0x79, 0x06, 0x22, 0x44, 0x9d, 0xf2, 0x26, 0xab, 0x29, 0x44, 0xe2, 0xb8, 0xe8, 0x2d, 0x42, 0x21, 0xc0, 0x6c, 0x53, 0xee, 0x57, 0x93, 0xec, 0xdd, 0x2c, 0xb8, 0xb4, 0x72, 0xdd, 0x5f, 0xf5, 0x98, 0x3e, 0x14, 0x9e, 0x51, 0x8f, 0x4a, 0xa9, 0x4c, 0x92, 0x00, 0x16, 0x18, 0xf7, 0x76, 0x5f, 0xa6, 0x54, 0xc2, 0x48, 0xce, 0xcd, 0xbd, 0xff, 0xf9, 0xe2, 0x1a, 0xc2, 0xe8, 0x11, 0xf8, 0xbf, 0x9e, 0x2a, 0xd1, 0x94, 0xee, 0x7d, 0x1b, 0xb3, 0x88, 0xa5, 0xa0, 0x6b, 0xfb, 0xd9, 0x4a, 0x09, 0xfa, 0x84, 0x18, 0x85, 0xac, 0x0b, 0xbc, 0xdc, 0xf3, 0xbf, 0xae, 0xaf, 0xfb, 0xc2, 0x98, 0x67, 0xd7, 0xbd, 0xf0, 0xc6, 0xe0, 0xa4, 0xa0, 0xb2, 0x67, 0x9e, 0x53, 0xea, 0x63, 0x35, 0x1d, 0xf7, 0x4e, 0x13, 0xee, 0xd9, 0x11, 0x61, 0xd0, 0x15, 0xa2, 0xf6, 0x70, 0x5b, 0x82, 0x73, 0xb0, 0xf0, 0xcf, 0x88, 0xd7, 0x90, 0xe8, 0xda, 0x54, 0x72, 0x68, 0xce, 0x51, 0x67, 0x1a, 0xc8, 0x03, 0xc9, 0x6c, 0x0c, 0x11, 0x8d, 0xc4, 0xf2, 0x0f, 0xaa, 0xf6, 0x28, 0x27, 0xc5, 0xab, 0xb2, 0xa1, 0x38, 0x30, 0xfa, 0xa3, 0x2b, 0x13, 0x02, 0x03, 0x01, 0x00, 0x01};
#endif

static uint32_t funcSwap32(uint32_t input)
{
	return OSSwapBigToHostInt32(input);
}

static uint32_t funcNoSwap32(uint32_t input)
{
	return OSSwapLittleToHostInt32(input);
}

/*
 * Magic numbers used by Code Signing
 */
enum {
	kSecCodeMagicRequirement = 0xfade0c00,		/* single requirement */
	kSecCodeMagicRequirementSet = 0xfade0c01,	/* requirement set */
	kSecCodeMagicCodeDirectory = 0xfade0c02,	/* CodeDirectory */
	kSecCodeMagicEmbeddedSignature = 0xfade0cc0, /* single-architecture embedded signature */
	kSecCodeMagicDetachedSignature = 0xfade0cc1, /* detached multi-architecture signature */
	kSecCodeMagicEntitlement = 0xfade7171,		/* entitlement blob */
	
	kSecCodeMagicByte = 0xfa					/* shared first byte */
};


/*
 * Structure of an embedded-signature SuperBlob
 */
typedef struct __BlobIndex {
	uint32_t type;					/* type of entry */
	uint32_t offset;				/* offset of entry */
} CS_BlobIndex;

typedef struct __Blob {
	uint32_t magic;					/* magic number */
	uint32_t length;				/* total length of SuperBlob */
} CS_Blob;

typedef struct __SuperBlob {
	CS_Blob blob;
	uint32_t count;					/* number of index entries following */
	CS_BlobIndex index[];			/* (count) entries */
	/* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;


/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
	uint32_t magic;					/* magic number (CSMAGIC_CODEDIRECTORY) */
	uint32_t length;				/* total length of CodeDirectory blob */
	uint32_t version;				/* compatibility version */
	uint32_t flags;					/* setup and mode flags */
	uint32_t hashOffset;			/* offset of hash slot element at index zero */
	uint32_t identOffset;			/* offset of identifier string */
	uint32_t nSpecialSlots;			/* number of special hash slots */
	uint32_t nCodeSlots;			/* number of ordinary (code) hash slots */
	uint32_t codeLimit;				/* limit to main image signature range */
	uint8_t hashSize;				/* size of each hash in bytes */
	uint8_t hashType;				/* type of hash (cdHashType* constants) */
	uint8_t spare1;					/* unused (must be zero) */
	uint8_t	pageSize;				/* log2(page size in bytes); 0 => infinite */
	uint32_t spare2;				/* unused (must be zero) */
	/* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;

BOOL parsePKCS7(const unsigned char* buffer, size_t size)
{
	BOOL result = NO;
	PKCS7* pkcs7 = NULL;
	STACK_OF(X509)* signers = NULL;
	
	pkcs7 = d2i_PKCS7(NULL, &buffer, size);
	if (pkcs7 == NULL)
	{
		goto error;
	}
	
	if (!PKCS7_type_is_signed(pkcs7))
	{
		goto error;
	}
	
	signers = PKCS7_get0_signers(pkcs7, NULL, PKCS7_BINARY);
	if (signers == NULL)
	{
		goto error;
	}
	
	const X509* cert = sk_X509_pop(signers);
	if (cert == NULL)
	{
		goto error;
	}
	
	printf("Signer name: %s\n", cert->name);
	printf("Signature length: %d, signature: ", cert->cert_info->key->public_key->length);
	
	for (int i = 0; i < cert->cert_info->key->public_key->length; i++)
	{
		printf("0x%02x, ", cert->cert_info->key->public_key->data[i]);
	}
	printf("\n");
	
	if (memcmp(PUBLIC_KEY, cert->cert_info->key->public_key->data, cert->cert_info->key->public_key->length) == 0)
	{
		printf("The same\n");
	}
    else
    {
        printf("Not the same\n");
    }
	
	result = YES;
	
error:
	if (signers) sk_X509_free(signers);
	if (pkcs7) PKCS7_free(pkcs7);
	
	return result;
}

BOOL parseSignature(const char* buffer, size_t size)
{
	printf("Signature\n");
	
	CS_SuperBlob* sb = (CS_SuperBlob*)buffer;
    if (OSSwapBigToHostInt32(sb->blob.magic) != kSecCodeMagicEmbeddedSignature)
	{
		return NO;
	}
	
	uint32_t count = OSSwapBigToHostInt32(sb->count);
	
	for (uint32_t i = 0; i < count; i++)
	{
        uint32_t offset = OSSwapBigToHostInt32(sb->index[i].offset);
        
		const CS_Blob* blob = (const CS_Blob*)(buffer + offset);
		
        if (OSSwapBigToHostInt32(blob->magic) == 0xfade0b01) //signature
		{
			printf("Embedded signature, length: %d\n", OSSwapBigToHostInt32(blob->length));
			
			if (OSSwapBigToHostInt32(blob->length) != 8)
			{
//				FILE* f = fopen("/Users/elviss/Desktop/signature.txt", "wb");
//				fwrite(buffer + offset + 8, OSSwapBigToHostInt32(blob->length) - 8, 1, f);
//				fclose(f);
				
				const unsigned char* message = (const unsigned char*)buffer + offset + 8;
				
				if (parsePKCS7(message, (OSSwapBigToHostInt32(blob->length) - 8)) == NO)
				{
					return NO;
				}
			}
		}
	}
	
	return YES;
}

BOOL parseArch(const char* buffer, size_t size)
{
	printf("Arch\n");
	
	uint32_t (*swap32)(uint32_t) = funcNoSwap32;
	
	uint32_t offset = 0;
	
	const struct mach_header* header = (struct mach_header*)(buffer + offset);
	
	switch (header->magic)
	{
		case MH_CIGAM:
			swap32 = funcSwap32;
		case MH_MAGIC:
			offset += sizeof(struct mach_header);
			break;
		case MH_CIGAM_64:
			swap32 = funcSwap32;
		case MH_MAGIC_64:
			offset += sizeof(struct mach_header_64);
			break;
		default:
			return NO;
	}
	
	//TODO: remove
	const NXArchInfo *archInfo = NXGetArchInfoFromCpuType(swap32(header->cputype), swap32(header->cpusubtype));
	if (archInfo != NULL)
	{
		printf("Architecture: %s\n", archInfo->name);
	}
	
	uint32_t commandCount = swap32(header->ncmds);
	
	for (uint32_t i = 0; i < commandCount; i++)
	{
		const struct load_command* loadCommand = (const struct load_command*)(buffer + offset);
		uint32_t commandSize = swap32(loadCommand->cmdsize);
		
		uint32_t commandType = swap32(loadCommand->cmd);
		if (commandType == LC_CODE_SIGNATURE)
		{
			const struct linkedit_data_command* dataCommand = (const struct linkedit_data_command*)(buffer + offset);
			uint32_t dataOffset = swap32(dataCommand->dataoff);
			uint32_t dataSize = swap32(dataCommand->datasize);
			
			return parseSignature(buffer + dataOffset, dataSize);
		}
		
		offset += commandSize;
	}
	
	//no signature found
	return NO;
}

BOOL parseFat(const char* buffer, size_t size)
{
	printf("FAT\n");
	
	size_t offset = 0;
	
	const struct fat_header* fatHeader = (const struct fat_header*)(buffer + offset);
	offset += sizeof(*fatHeader);
	
	uint32_t archCount = OSSwapBigToHostInt32(fatHeader->nfat_arch);
	
	printf("Arch count: %d\n", archCount);
	
	for (uint32_t i = 0; i < archCount; i++)
	{
		const struct fat_arch* arch = (const struct fat_arch*)(buffer + offset);
		offset += sizeof(*arch);
		
		uint32_t archOffset = OSSwapBigToHostInt32(arch->offset);
		uint32_t archSize = OSSwapBigToHostInt32(arch->size);
		
		if (!parseArch(buffer + archOffset, archSize))
		{
			return NO;
		}
	}
	
	return YES;
}

BOOL parseMachO(const char* buffer, size_t size)
{
	const uint32_t* magic = (const uint32_t*)buffer;
	
	if (*magic == FAT_CIGAM ||
		*magic == FAT_MAGIC)
	{
		return parseFat(buffer, size);
	}
	else
	{
		return parseArch(buffer, size);
	}
}

BOOL checkSignature()
{
	BOOL result = NO;
	char* buffer = NULL;
	
	NSString* appPath = [[NSBundle mainBundle] executablePath];
	printf("Path: %s\n", [appPath cStringUsingEncoding:NSASCIIStringEncoding]);
	
    //const char* filename = [appPath cStringUsingEncoding:NSASCIIStringEncoding];
    const char* filename = "/Applications/TextWrangler.app/Contents/MacOS/TextWrangler";
    
	int fd = open(filename, O_RDONLY);
	//int fd = open("/Users/elviss/Library/Developer/Xcode/DerivedData/SwiftTest-btixclnafwwpwdgofdfhjuzmntot/Build/Products/Debug-iphoneos/SwiftTest.app/SwiftTest", O_RDONLY);
	
	//int fd = open("/Users/elviss/Desktop/app/ParticleCreator 1.0/Payload/ParticleCreator.app/ParticleCreator", O_RDONLY);
	
	if (fd == -1)
	{
		goto error;
	}
	
	struct stat st;
	fstat(fd, &st);
	
	buffer = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_FILE|MAP_PRIVATE, fd, 0);
	
	if (buffer == MAP_FAILED)
	{
		goto error;
	}
	
	printf("File opened\n");
	
	result = parseMachO(buffer, (size_t)st.st_size);
	
error:
	if (buffer) munmap(buffer, (size_t)st.st_size);
	if (fd != -1) close(fd);
	
	return result;
}

int main(int argc, const char * argv[])
{
	if (checkSignature())
	{
		printf("OK\n");
	}
	
    return 0;
}

