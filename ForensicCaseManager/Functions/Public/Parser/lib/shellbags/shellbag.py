import os
import sys
import glob
import base64
import OverTheShellbag as shellbag

def path_finder(bag_path):
    value = path_dict[bag_path]
    s     = bag_path.split('\\')
    if len(s) > 1:
        parent_path = '\\'.join(s[:-1])
        return path_finder(parent_path) + '\\' + value
    else:
        return value


if __name__ == '__main__':
    item_path                = sys.argv[1]
    shellbag_analysis_result = list()
    
    if os.path.isdir(item_path): 
        hive_files = [path for path in glob.glob(os.path.join(item_path, "*.*"), recursive=True) if os.path.isfile(path)] 

        for file in hive_files:
            file_name    = os.path.split(file)[1].lower()
            file_objects = {
                "primary" : None,
                "log1"    : None,
                "log2"    : None
            }

            if file_name == 'usrclass.dat':
                file_objects['primary'] = open(file, 'rb')
            if file_name == 'usrclass.dat.log1':
                file_objects['log1']    = open(file, 'rb')
            if file_name == 'usrclass.dat.log2':
                file_objects['log2']    = open(file, 'rb')

            try:
                parse_results = shellbag.Main(file_objects)
            except Exception:
                sys.exit()

            path_dict           = dict()
            path_dict['BagMRU'] = 'Desktop'
            
            for result in parse_results:
                path_dict[result[0]] = result[2]
                        
            for result in parse_results:
                artifact_info                      = dict()
                artifact_info['BagPath']           = result[0]
                artifact_info['ShellType']         = result[1]
                artifact_info['Value']             = str(base64.b64encode(result[2].encode('utf-8'))).strip('b').strip("'")
                # artifact_info['AbsolutePath']      = str(base64.b64encode((path_finder(result[0])).encode('utf-8'))).strip('b').strip("'")
                artifact_info['TimeModified']      = result[3]
                artifact_info['TimeAccessed']      = result[4]
                artifact_info['TimeCreated']       = result[5]
                artifact_info['LastWrite']         = result[6]
                artifact_info['MftEntryNumber']    = result[7]
                artifact_info['MftSequenceNumber'] = result[8]
                artifact_info['FileSystem']        = result[9]
                artifact_info['Category']          = 'FolderOpened'
                artifact_info['Artifact']          = 'Shellbag'
                artifact_info['Source']            = str(base64.b64encode(file.encode('utf-8'))).strip('b').strip("'")
                shellbag_analysis_result.append(artifact_info)

            print(shellbag_analysis_result)            

    else:
        file_name    = os.path.split(item_path)[1].lower()
        file_objects = {
            "primary" : None,
            "log1"    : None,
            "log2"    : None
        }

        if file_name == 'usrclass.dat':
            file_objects['primary'] = open(item_path, 'rb')
        if file_name == 'usrclass.dat.log1':
            file_objects['log1']    = open(item_path, 'rb')
        if file_name == 'usrclass.dat.log2':
            file_objects['log2']    = open(item_path, 'rb')

        try:
            parse_results = shellbag.Main(file_objects)
        except Exception:
            sys.exit()

        path_dict           = dict()
        path_dict['BagMRU'] = 'Desktop'
        
        for result in parse_results:
            path_dict[result[0]] = result[2]

        for result in parse_results:
            artifact_info                      = dict()
            artifact_info['BagPath']           = result[0]
            artifact_info['ShellType']         = result[1]
            artifact_info['Value']             = str(base64.b64encode(result[2].encode('utf-8'))).strip('b').strip("'")
            # artifact_info['AbsolutePath']      = str(base64.b64encode((path_finder(result[0])).encode('utf-8'))).strip('b').strip("'")
            artifact_info['TimeModified']      = result[3]
            artifact_info['TimeAccessed']      = result[4]
            artifact_info['TimeCreated']       = result[5]
            artifact_info['LastWrite']         = result[6]
            artifact_info['MftEntryNumber']    = result[7]
            artifact_info['MftSequenceNumber'] = result[8]
            artifact_info['FileSystem']        = result[9]
            artifact_info['Category']          = 'FolderOpened'
            artifact_info['Artifact']          = 'Shellbag'
            artifact_info['Source']            = str(base64.b64encode(item_path.encode('utf-8'))).strip('b').strip("'")
            shellbag_analysis_result.append(artifact_info)

        print(shellbag_analysis_result)