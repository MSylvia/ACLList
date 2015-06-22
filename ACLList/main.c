//
//  main.c
//  ACLList
//
//  Created by Matthew Sylvia on 6/22/15.
//  Copyright (c) 2015 Matthew Sylvia. All rights reserved.
//

// Modified from:
// https://developer.apple.com/library/mac/documentation/Security/Conceptual/keychainServConcepts/03tasks/tasks.html#//apple_ref/doc/uid/TP30000897-CH205-BBCHEABI

#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>


//Get an ACL out of a CFArray:
SecACLRef GetACL (CFIndex numACLs, CFArrayRef ACLList,
                  CFArrayRef *applicationList, CFStringRef *description,
                  SecKeychainPromptSelector *promptSelector)
{
    OSStatus status;
    //Because we limited our search to ACLs used for decryption, we
    // expect only one ACL for this item. Therefore, we extract the
    // application list from the first ACL in the array.
    const SecACLRef acl = (SecACLRef) CFArrayGetValueAtIndex(ACLList, 0);
    status = SecACLCopyContents (
                                 acl,                    // the ACL from which to extract
                                 //  the list of trusted apps
                                 applicationList,        // the list of trusted apps
                                 description,            // the description string
                                 promptSelector          // the value of the prompt selector flag
                                 );
    
    if (status == noErr) {
        return acl;
    } else {
        return NULL;
    }
}

void printStatus(OSStatus status)
{
    const char* sstatus = GetMacOSStatusErrorString(status);
    const char* sdesc   = GetMacOSStatusCommentString(status);
    
    printf("%s Status= %s %s\n", status == noErr ? "✓":"✕", sstatus, sdesc);
}

int modifyTheACL(const char *labelString)
{
    OSStatus status;
    
    SecKeychainSearchRef searchReference = NULL;
    SecKeychainItemRef itemRef = NULL;
    
    SecAccessRef itemAccess = NULL;
    SecACLRef oldACL = NULL, newACL = NULL;
    
    CFIndex arrayCount;
    CFRange arrayRange;
    SecTrustedApplicationRef trustedAppArray[10];
    SecKeychainPromptSelector promptSelector;
    
    CFStringRef description = NULL;
    CFArrayRef newTrustedAppArray = NULL;
    SecTrustedApplicationRef trustedApp = NULL;
    
    //path to trusted app to add to ACL
    const char *path = "/Applications/Mail.app";
    
    /* Construct a search dictionary to find the desired item. */
    CFStringRef label    = CFStringCreateWithCString(NULL, labelString, kCFStringEncodingUTF8);
    const void *keys[]   = { kSecClass, kSecAttrLabel, kSecReturnRef };
    const void *values[] = { kSecClassCertificate, label, kCFBooleanTrue };
    
 
    CFDictionaryRef searchDict = CFDictionaryCreate(kCFAllocatorDefault,
                                                    keys,
                                                    values,
                                                    3,
                                                    &kCFTypeDictionaryKeyCallBacks,
                                                    &kCFTypeDictionaryValueCallBacks);
    
    CFArrayRef aclList = NULL;
    CFIndex numACLs = 0;
    CFArrayRef applicationList;
    // the authorization tag to search for.
    CFTypeRef authorizationTag = kSecACLAuthorizationDecrypt;
    
    // Find the keychain item and obtain a keychain item reference object.
    // This returns a SecKeychainItemRef, which we must release when
    //  we're finished using it.
    status = SecItemCopyMatching(searchDict, (CFTypeRef *)&itemRef);
    
    printStatus(status);
    
    if (status == noErr)
    {
        // Obtain the access reference object for the keychain item.
        // This returns a SecAccessRef, which we must release when
        //  we're finished using it.
        status = SecKeychainItemCopyAccess (itemRef, &itemAccess);
        // Obtain an array of ACL entry objects for the access object.
        // Limit the search to ACL entries with the specified
        //  authorization tag.
  
        // This should not be null :(
        if (itemAccess == NULL) {
            printf("This should not be NULL! (╯°□°）╯︵ ┻━┻ \n");
        }
        
        if (status != noErr)
            return status;
        
        aclList = SecAccessCopyMatchingACLList(itemAccess, authorizationTag);
        numACLs = CFArrayGetCount (aclList);
        // Code –25243 | Description | The specified item has no access control.
        
        // Extract the ACL entry object from the array of ACL entries,
        //  along with the ACL entry's list of trusted applications,
        //  its description, and its prompt selector flag setting.
        // This returns a SecACLRef and a CFArrayRef, which we must
        //  release we're finished using them.
        oldACL = GetACL (numACLs, aclList, &applicationList, &description, &promptSelector);
        if (oldACL) {
            CFRetain(oldACL);
        }
        arrayCount = CFArrayGetCount (applicationList);
        
        //  The application list is a CFArray.  Extract the list of
        //  applications from the CFArray.
        arrayRange.location = (CFIndex) 0;
        arrayRange.length = arrayCount;
        CFArrayGetValues (applicationList, arrayRange,
                          (void *) trustedAppArray);
        // Create a new trusted application reference object for
        //  the application to be added to the list.
        status = status ?: SecTrustedApplicationCreateFromPath (path, &trustedApp);
        if (status == noErr)   // the function fails if the application is
            // not found.
        {
            // Append the new application to the array and create a
            //  new CFArray.
            trustedAppArray[arrayCount] = trustedApp;
            newTrustedAppArray = CFArrayCreate (NULL,
                                                (void *)trustedAppArray, arrayCount+1,
                                                &kCFTypeArrayCallBacks);
            // Get the authorizations from the old ACL.
            CFArrayRef authorizations = SecACLCopyAuthorizations(oldACL);
            
            // Delete the old ACL from the access object. The user is
            // prompted for permission to alter the keychain item.
            status = status ?: SecACLRemove (oldACL);
            
            // Create a new ACL with the same attributes as the old
            // one, except use the new CFArray of trusted applications.
            status = status ?: SecACLCreateWithSimpleContents (itemAccess,
                                                               newTrustedAppArray, description, promptSelector,
                                                               &newACL);
            // Set the authorizations for the new ACL to be the same as
            //  those for the old ACL.
            status = status ?: SecACLUpdateAuthorizations (newACL, authorizations);
            
            // Replace the access object in the keychain item with the
            //  new access object. The user is prompted for permission
            //  to alter the keychain item.
            status = status ?: SecKeychainItemSetAccess (itemRef, itemAccess);
            
            CFRelease(authorizations);
        }
        else {
            // Handle the error if the application was not found.
            // ...
        }
        
        // Release the objects we allocated or retrieved
        if (searchReference)
            CFRelease(searchReference);     //SecKeychainSearchRef
        if (itemRef)
            CFRelease(itemRef);             //SecKeychainItemRef
        if (itemAccess)
            CFRelease(itemAccess);          //SecAccessRef
        if (oldACL)
            CFRelease(oldACL);              //SecACLRef
        if (newACL)
            CFRelease(newACL);              //SecACLRef
        if (description)
            CFRelease(description);         //CFStringRef
        if (newTrustedAppArray)
            CFRelease(newTrustedAppArray);  //CFArrayRef
        if (trustedApp)
            CFRelease(trustedApp);          //SecTrustedApplicationRef
        if (aclList)
            CFRelease(aclList);             //CFArrayRef
        if (applicationList)
            CFRelease(applicationList);     //CFArrayRef
    }
    return (status);
    
}

int main(int argc, const char * argv[]) {
    printf("Gathering Access Control list for \"%s\"\n", argv[1]);
    OSStatus status = modifyTheACL(argv[1]);
    printStatus(status);
    return 0;
}

