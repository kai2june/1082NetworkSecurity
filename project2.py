import xml.etree.ElementTree as ET
import pandas as pd
import numpy as np
import re
import datetime
import time
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB

def parse_security(person_number):
    # parse security.XML
    EventID = np.array([])
    Version = np.array([])
    Level = np.array([])
    Task = np.array([])
    Opcode = np.array([])
    Keywords = np.array([])
    SystemTime = np.array([])  # attrib
    EventRecordID = np.array([])
    ActivityID = np.array([])  # attrib
    ProcessID = np.array([])  # attrib
    ThreadID = np.array([])  # attrib
    Channel = np.array([])
    Computer = np.array([])
    SubjectUserSid = np.array([])
    SubjectUserName = np.array([])
    SubjectDomainName = np.array([])
    SubjectLogonId = np.array([])
    PrivilegeList = np.array([])
    input_file = './Logs/Train/Person_' + str(person_number) + '/Security.xml'
    tree = ET.parse(input_file)
    root = tree.getroot()
    for Event in root:
        for item in Event[0]:
            if "EventID" in item.tag:
                EventID = np.append(EventID, int(item.text))
            elif "Version" in item.tag:
                Version = np.append(Version, int(item.text))
            elif "Level" in item.tag:
                Level = np.append(Level, int(item.text))
            elif "Task" in item.tag:
                Task = np.append(Task, int(item.text))
            elif "Opcode" in item.tag:
                Opcode = np.append(Opcode, int(item.text))
            elif "Keywords" in item.tag:
                Keywords = np.append(Keywords, int(item.text, 16)) ## hex to intbase10
            elif "TimeCreated" in item.tag:
                time_record = item.attrib['SystemTime']
                year = int(time_record.split('-')[0])
                month = int(time_record.split('-')[1])
                day = time_record.split('-')[2]
                day = int(day.split('T')[0])
                hour = time_record.split('T')[1]
                hour = int(hour.split(':')[0])
                minute = int(time_record.split(':')[1])
                second = time_record.split(':')[2]
                second = int(second.split('.')[0])
                dt = datetime.datetime(year, month, day, hour, minute, second)
                time_in_sec = time.mktime(dt.timetuple())
                SystemTime = np.append(SystemTime, time_in_sec) ## change to seconds
            elif "EventRecordID" in item.tag:
                EventRecordID = np.append(EventRecordID, int(item.text)) 
            # elif "Correlation" in item.tag:
            #     if item.attrib == {}:
            #         ActivityID = np.append(ActivityID, -1)
            #     else:
            #         acID = str(item.attrib)
            #         # print(acID.split('{'))
            #         acID = acID.split('{')[2]
            #         acID = acID.split('}')[0]
            #         ActivityID = np.append(ActivityID, acID) ## change to 不同編號
            elif "Execution" in item.tag:
                ProcessID = np.append(ProcessID, int(item.attrib['ProcessID'])) 
                ThreadID = np.append(ThreadID, int(item.attrib['ThreadID'])) 
        #     elif "Channel" in item.tag:
        #         Channel = np.append(Channel, item.text) ## change to 不同編號
        #     elif "Computer" in item.tag:
        #         Computer = np.append(Computer, item.text) ## change to 不同編號
        # for item in Event[1]:
        #     if "SubjectUserSid" in item.attrib["Name"]:
        #         SubjectUserSid = np.append(SubjectUserSid, item.text)
        #     elif "SubjectUserName" in item.attrib["Name"]:
        #         SubjectUserName = np.append(SubjectUserName, item.text)
        #     elif "SubjectDomainName" in item.attrib["Name"]:
        #         SubjectDomainName = np.append(SubjectDomainName, item.text)
        #     elif "SubjectLogonId" in item.attrib["Name"]:
        #         SubjectLogonId = np.append(SubjectLogonId, int(item.text, 16)) ## hex to intbase10
    # print("EventID", len(EventID))
    # print("Version", len(Version))
    # print("Level", len(Level))
    # print("Task", len(Task))
    # print("Opcode", len(Opcode))
    # print("Keywords", len(Keywords))
    # print("SystemTime", len(SystemTime))
    # print("EventRecordID", len(EventRecordID))
    # print("ActivityID", len(ActivityID))
    # print("ProcessID", len(ProcessID))
    # print("ThreadID", len(ThreadID))
    # print("Channel", len(Channel))
    # print("Computer", len(Computer))
    # print("SubjectUserSid", len(SubjectUserSid))
    # print("SubjectUserName", len(SubjectUserName))
    # print("SubjectDomainName", len(SubjectDomainName))
    # print("SubjectLogonId", len(SubjectLogonId))

    # feature = {'EventID': EventID, 'Version': Version, 'Level': Level, 'Task': Task, 'Opcode': Opcode, 'Keywords': Keywords, 'SystemTime': SystemTime
    #     , 'EventRecordID': EventRecordID, 'ActivityID': ActivityID, 'ProcessID': ProcessID, 'ThreadID': ThreadID, 'Channel': Channel, 'Computer': Computer
    #     , 'SubjectUserSid': SubjectUserSid, 'SubjectUserName': SubjectUserName, 'SubjectDomainName': SubjectDomainName, 'SubjectLogonId': SubjectLogonId}
    feature = {'EventID': EventID, 'Version': Version, 'Level': Level, 'Task': Task, 'Opcode': Opcode, 'Keywords': Keywords, 'SystemTime': SystemTime
        , 'EventRecordID': EventRecordID, 'ProcessID': ProcessID, 'ThreadID': ThreadID}

    df = pd.DataFrame(feature)
    # print(df)
    return df

# assign label
label = np.zeros(81 + 53 + 4459 + 341 + 712 + 47)
for idx in range(81):
    label[idx] = 1
for idx in range(81, 134):
    label[idx] = 2
for idx in range(134, 4593):
    label[idx] = 3
for idx in range(4593, 4934):
    label[idx] = 4
for idx in range(4934, 5646):
    label[idx] = 5
for idx in range(5646, 5693):
    label[idx] = 6

df_feature1 = parse_security(1)
df_feature2 = parse_security(2)
df_feature3 = parse_security(3)
df_feature4 = parse_security(4)
df_feature5 = parse_security(5)
df_feature6 = parse_security(6)

training_feature = pd.concat([df_feature1, df_feature2, df_feature3, df_feature4, df_feature5, df_feature6], ignore_index=True)
training_label = pd.DataFrame(label)

print(training_feature)
print(training_label)

# fit model 
X_train, X_test, y_train, y_test = train_test_split(training_feature, training_label, test_size=0.2, random_state=42)
gnb = GaussianNB() 
y_pred = gnb.fit(X_train, y_train.values.ravel()).predict(X_test)
