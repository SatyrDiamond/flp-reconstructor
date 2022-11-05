# SPDX-FileCopyrightText: 2022 Colby Ray
# SPDX-License-Identifier: GPL-3.0-or-later

import varint
import argparse
import struct
from io import BytesIO

# ------------- Functions -------------
def create_bytesio(data):
    bytesio = BytesIO()
    bytesio.write(data)
    bytesio.seek(0,2)
    bytesio_filesize = bytesio.tell()
    bytesio.seek(0)
    return [bytesio, bytesio_filesize]
def readriffdata(riffbytebuffer, offset):
    if isinstance(riffbytebuffer, (bytes, bytearray)) == True:
        riffbytebuffer = bytearray2BytesIO(riffbytebuffer)
    riffobjects = []
    riffbytebuffer.seek(0,2)
    filesize = riffbytebuffer.tell()
    riffbytebuffer.seek(offset)
    while filesize > riffbytebuffer.tell():
        chunkname = riffbytebuffer.read(4)
        chunksize = int.from_bytes(riffbytebuffer.read(4), "little")
        chunkdata = riffbytebuffer.read(chunksize)
        riffobjects.append([chunkname, chunkdata])
    return riffobjects

# ------------- deconstruct -------------
def deconstruct_arrangement(arrdata):
    bio_fldata = create_bytesio(arrdata)
    output = []
    while bio_fldata[0].tell() < bio_fldata[1]:
        placement = {}
        placement['position'] = int.from_bytes(bio_fldata[0].read(4), "little")
        placement['patternbase'] = int.from_bytes(bio_fldata[0].read(2), "little")
        placement['itemindex'] = int.from_bytes(bio_fldata[0].read(2), "little")
        placement['length'] = int.from_bytes(bio_fldata[0].read(4), "little")
        placement['trackindex'] = int.from_bytes(bio_fldata[0].read(4), "little")
        placement['unknown1'] = int.from_bytes(bio_fldata[0].read(2), "little")
        placement['flags'] = int.from_bytes(bio_fldata[0].read(2), "little")
        placement['unknown2'] = int.from_bytes(bio_fldata[0].read(2), "little")
        placement['unknown3'] = int.from_bytes(bio_fldata[0].read(2), "little")
        startoffset = int.from_bytes(bio_fldata[0].read(4), "little")
        endoffset = int.from_bytes(bio_fldata[0].read(4), "little")
        if startoffset != 4294967295: placement['startoffset'] = startoffset
        if endoffset != 4294967295: placement['endoffset'] = endoffset
        output.append(placement)
    return output
def deconstruct_trackinfo(trackdata):
    bio_fltrack = create_bytesio(trackdata)[0]
    params = {}
    trackid = int.from_bytes(bio_fltrack.read(4), "little")
    params['color'] = int.from_bytes(bio_fltrack.read(4), "little")
    params['icon'] = int.from_bytes(bio_fltrack.read(4), "little")
    params['enabled'] = int.from_bytes(bio_fltrack.read(1), "little")
    params['height'] = struct.unpack('<f', bio_fltrack.read(4))[0]
    params['lockedtocontent'] = int.from_bytes(bio_fltrack.read(1), "little")
    params['motion'] = int.from_bytes(bio_fltrack.read(4), "little")
    params['press'] = int.from_bytes(bio_fltrack.read(4), "little")
    params['triggersync'] = int.from_bytes(bio_fltrack.read(4), "little")
    params['queued'] = int.from_bytes(bio_fltrack.read(4), "little")
    params['tolerant'] = int.from_bytes(bio_fltrack.read(4), "little")
    params['positionSync'] = int.from_bytes(bio_fltrack.read(4), "little")
    params['grouped'] = int.from_bytes(bio_fltrack.read(1), "little")
    params['locked'] = int.from_bytes(bio_fltrack.read(1), "little")
    if params['color'] == 5656904 and params['icon'] == 0 and params['enabled'] == 1 and params['height'] == 1.0 and params['lockedtocontent'] == 255 and params['motion'] == 16777215 and params['press'] == 0 and params['triggersync'] == 0 and params['queued'] == 5 and params['tolerant'] == 0 and params['positionSync'] == 1 and params['grouped'] == 0 and params['locked'] == 0:
        return [trackid, None]
    else:
        return [trackid, params]
def deconstruct_fxrouting(fxroutingbytes):
    fxroutingdata = create_bytesio(fxroutingbytes)
    fxcount = 0
    routes = []
    while fxroutingdata[0].tell() < fxroutingdata[1]:
        fxchannel = int.from_bytes(fxroutingdata[0].read(1), "little")
        if fxchannel == 1:
            routes.append(fxcount)
        fxcount += 1
    return routes
def deconstruct_flevent(datastream):
    event_id = int.from_bytes(datastream.read(1), "little")
    if event_id <= 63 and event_id >= 0: # int8
        event_data = int.from_bytes(eventdatastream.read(1), "little")
    if event_id <= 127 and event_id >= 64 : # int16
        event_data = int.from_bytes(eventdatastream.read(2), "little")
    if event_id <= 191 and event_id >= 128 : # int32
        event_data = int.from_bytes(eventdatastream.read(4), "little")
    if event_id <= 224 and event_id >= 192 : # text
        eventpartdatasize = varint.decode_stream(datastream)
        event_data = datastream.read(eventpartdatasize)
    if event_id <= 255 and event_id >= 225 : # data
        eventpartdatasize = varint.decode_stream(datastream)
        event_data = datastream.read(eventpartdatasize)
    return [event_id, event_data]
def deconstruct(inputfile):
    fileobject = open(inputfile, 'rb')
    headername = fileobject.read(4)
    rifftable = readriffdata(fileobject, 0)
    for riffobj in rifftable:
        ##print(str(riffobj[0]) + str(len(riffobj[1])))
        if riffobj[0] == b'FLhd':
            ##print('Channels:', int.from_bytes(riffobj[1][0:3], "big"))
            flp_ppq = int.from_bytes(riffobj[1][4:6], "little")
            ##print('PPQ:',str(flp_ppq))
        if riffobj[0] == b'FLdt':
            mainevents = riffobj[1]
            global eventdatastream
            eventdatasize = len(mainevents)
            eventdatastream = BytesIO()
            eventdatastream.write(mainevents)
            eventdatastream.seek(0)
            eventtable = []
            while eventdatastream.tell() < int(eventdatasize):
                event_id = int.from_bytes(eventdatastream.read(1), "little")
                if event_id <= 63 and event_id >= 0: # int8
                    event_data = int.from_bytes(eventdatastream.read(1), "little")
                if event_id <= 127 and event_id >= 64 : # int16
                    event_data = int.from_bytes(eventdatastream.read(2), "little")
                if event_id <= 191 and event_id >= 128 : # int32
                    event_data = int.from_bytes(eventdatastream.read(4), "little")
                if event_id <= 224 and event_id >= 192 : # text
                    eventpartdatasize = varint.decode_stream(eventdatastream)
                    event_data = eventdatastream.read(eventpartdatasize)
                if event_id <= 255 and event_id >= 225 : # data
                    eventpartdatasize = varint.decode_stream(eventdatastream)
                    event_data = eventdatastream.read(eventpartdatasize)
                eventtable.append([event_id, event_data])
    
    FL_Main = {}
    FL_Channels = {}
    FL_Tracks = {}
    FL_Patterns = {}
    FL_Mixer = {}
    for fxnum in range(127):
        FL_Mixer[str(fxnum)] = {}
    FL_TimeMarkers = {}

    TimeMarker_id = 0
    FL_Arrangements = {}
    FL_FXCreationMode = 0
    T_FL_FXNum = -1

    for event in eventtable:
        event_id = event[0]
        event_data = event[1]
        if event_id == 199: FL_Main['Version'] = event_data.decode('utf-8').rstrip('\x00')
        if event_id == 156: FL_Main['Tempo'] = event_data/1000
        if event_id == 80: FL_Main['MainPitch'] = event_data
        if event_id == 17: FL_Main['Numerator'] = event_data
        if event_id == 18: FL_Main['Denominator'] = event_data
        if event_id == 11: FL_Main['Shuffle'] = event_data
        if event_id == 194: FL_Main['Title'] = event_data.decode('utf-16le').rstrip('\x00\x00')
        if event_id == 206: FL_Main['Genre'] = event_data.decode('utf-16le').rstrip('\x00\x00')
        if event_id == 207: FL_Main['Author'] = event_data.decode('utf-16le').rstrip('\x00\x00')
        if event_id == 202: FL_Main['ProjectDataPath'] = event_data.decode('utf-16le').rstrip('\x00\x00')
        if event_id == 195: FL_Main['Comment'] = event_data.decode('utf-16le').rstrip('\x00\x00')
        if event_id == 197: FL_Main['URL'] = event_data.decode('utf-16le').rstrip('\x00\x00')
        if event_id == 237: FL_Main['ProjectTime'] = event_data
        if event_id == 10: FL_Main['ShowInfo'] = event_data

    
        if event_id == 65: 
            T_FL_CurrentPattern = event_data
            #print('Pattern:', event_data)
        if event_id == 223: #AutomationData
            #print('\\__AutomationData')
            autodata = create_bytesio(event_data)
            autopoints = []
            while autodata[0].tell() < autodata[1]:
                pointdata = {}
                pointdata['pos'] = int.from_bytes(autodata[0].read(4), "little")
                pointdata['control'] = autodata[0].read(4)
                pointdata['value'] = autodata[0].read(4)
                autopoints.append(pointdata)
            if str(T_FL_CurrentPattern) not in FL_Patterns:
                FL_Patterns[str(T_FL_CurrentPattern)] = {}
            FL_Patterns[str(T_FL_CurrentPattern)]['automation'] = autopoints

        if event_id == 224: #PatternNotes
            #print('\\__PatternNotes')
            fl_notedata = create_bytesio(event_data)
            notelist = []
            while fl_notedata[0].tell() < fl_notedata[1]:
                notedata = {}
                notedata['pos'] = int.from_bytes(fl_notedata[0].read(4), "little")
                notedata['flags'] = int.from_bytes(fl_notedata[0].read(2), "little")
                notedata['rack'] = int.from_bytes(fl_notedata[0].read(2), "little")
                notedata['dur'] = int.from_bytes(fl_notedata[0].read(4), "little")
                notedata['key'] = int.from_bytes(fl_notedata[0].read(4), "little")
                notedata['finep'] = int.from_bytes(fl_notedata[0].read(1), "little")
                notedata['u1'] = int.from_bytes(fl_notedata[0].read(1), "little")
                notedata['rel'] = int.from_bytes(fl_notedata[0].read(1), "little")
                notedata['midich'] = int.from_bytes(fl_notedata[0].read(1), "little")
                notedata['pan'] = int.from_bytes(fl_notedata[0].read(1), "little")
                notedata['velocity'] = int.from_bytes(fl_notedata[0].read(1), "little")
                notedata['mod_x'] = int.from_bytes(fl_notedata[0].read(1), "little")
                notedata['mod_y'] = int.from_bytes(fl_notedata[0].read(1), "little")
                notelist.append(notedata)
            if str(T_FL_CurrentPattern) not in FL_Patterns:
                FL_Patterns[str(T_FL_CurrentPattern)] = {}
            FL_Patterns[str(T_FL_CurrentPattern)]['notes'] = notelist
    
        if event_id == 150: 
            FL_Patterns[str(T_FL_CurrentPattern)]['color'] = event_data

        if event_id == 238: #PLTrackInfo
            FLT_out = deconstruct_trackinfo(event_data)
            currenttracknum = FLT_out[0]
            if FLT_out[1] != None:
                FL_Tracks[str(currenttracknum)] = FLT_out[1]
        if event_id == 239: #PLTrackName
            FL_Tracks[str(currenttracknum)]['name'] = event_data.decode('utf-16le').rstrip('\x00\x00')

        if event_id == 99: 
            T_FL_CurrentArrangement = event_data
            #print('NewArrangement:', event_data)
            if str(T_FL_CurrentArrangement) not in FL_Arrangements:
                FL_Arrangements[str(T_FL_CurrentArrangement)] = {}
        if event_id == 241: 
            FL_Arrangements[str(T_FL_CurrentArrangement)]['name'] = event_data.decode('utf-16le').rstrip('\x00\x00')
        if event_id == 233: 
            playlistitems = deconstruct_arrangement(event_data)
            FL_Arrangements[str(T_FL_CurrentArrangement)]['items'] = playlistitems
    
    
        if event_id == 148: 
            TimeMarker_id += 1
            T_FL_CurrentTimeMarker = TimeMarker_id
            timemarkertype = event_data >> 24
            timemarkertime = event_data & 0x00ffffff
            #print('NewTimeMarker:', timemarkertime, timemarkertype)
            FL_TimeMarkers[str(T_FL_CurrentTimeMarker)] = {}
            FL_TimeMarkers[str(T_FL_CurrentTimeMarker)]['type'] = timemarkertype
            FL_TimeMarkers[str(T_FL_CurrentTimeMarker)]['pos'] = timemarkertime
        if event_id == 205: 
            event_text = event_data.decode('utf-16le').rstrip('\x00\x00')
            #print('\\__TimeMarkerName:', event_text)
            FL_TimeMarkers[str(T_FL_CurrentTimeMarker)]['name'] = event_text
        if event_id == 33: 
            #print('\\__TimeMarkerNumerator:', event_data)
            FL_TimeMarkers[str(T_FL_CurrentTimeMarker)]['numerator'] = event_data
        if event_id == 34: 
            #print('\\__TimeMarkerDenominator:', event_data)
            FL_TimeMarkers[str(T_FL_CurrentTimeMarker)]['denominator'] = event_data
    
    
        if event_id == 64: 
            T_FL_CurrentChannel = event_data
            #print('Channel:', event_data)
            if str(T_FL_CurrentChannel) not in FL_Channels:
                FL_Channels[str(T_FL_CurrentChannel)] = {}
        if event_id == 21: 
            #print('\\__Type:', event_data)
            FL_Channels[str(T_FL_CurrentChannel)]['type'] = event_data
    
    
    
        if event_id == 38: 
            FL_FXCreationMode = 1
            T_FL_FXColor = None
            T_FL_FXIcon = None
        if FL_FXCreationMode == 0:
            if event_id == 201: 
                event_text = event_data.decode('utf-16le').rstrip('\x00\x00')
                #print('\\__DefPluginName:', event_text)
                DefPluginName = event_text
            if event_id == 212:
                #print('\\__NewPlugin')
                FL_Channels[str(T_FL_CurrentChannel)]['plugin'] = DefPluginName
                FL_Channels[str(T_FL_CurrentChannel)]['chandata'] = event_data
                EnvelopeNum = 0
            if event_id == 203: 
                event_text = event_data.decode('utf-16le').rstrip('\x00\x00')
                #print('\\__PluginName:', event_text)
                FL_Channels[str(T_FL_CurrentChannel)]['name'] = event_text
            if event_id == 155: 
                FL_Channels[str(T_FL_CurrentChannel)]['icon'] = event_data
            if event_id == 128: 
                FL_Channels[str(T_FL_CurrentChannel)]['color'] = event_data
            if event_id == 213: FL_Channels[str(T_FL_CurrentChannel)]['pluginparams'] = event_data
            if event_id == 0: FL_Channels[str(T_FL_CurrentChannel)]['enabled'] = event_data
            if event_id == 218: 
                EnvelopeNum += 1
                if EnvelopeNum == 1: FL_Channels[str(T_FL_CurrentChannel)]['envlfo_pan'] = event_data
                if EnvelopeNum == 2: FL_Channels[str(T_FL_CurrentChannel)]['envlfo_vol'] = event_data
                if EnvelopeNum == 3: FL_Channels[str(T_FL_CurrentChannel)]['envlfo_modx'] = event_data
                if EnvelopeNum == 4: FL_Channels[str(T_FL_CurrentChannel)]['envlfo_mody'] = event_data
                if EnvelopeNum == 5: FL_Channels[str(T_FL_CurrentChannel)]['envlfo_pitch'] = event_data
            if event_id == 209: FL_Channels[str(T_FL_CurrentChannel)]['delay'] = event_data
            if event_id == 138: FL_Channels[str(T_FL_CurrentChannel)]['delayreso'] = event_data
            if event_id == 139: FL_Channels[str(T_FL_CurrentChannel)]['reverb'] = event_data
            if event_id == 89: FL_Channels[str(T_FL_CurrentChannel)]['shiftdelay'] = event_data
            if event_id == 69: FL_Channels[str(T_FL_CurrentChannel)]['fx'] = event_data
            if event_id == 86: FL_Channels[str(T_FL_CurrentChannel)]['fx3'] = event_data
            if event_id == 71: FL_Channels[str(T_FL_CurrentChannel)]['cutoff'] = event_data
            if event_id == 83: FL_Channels[str(T_FL_CurrentChannel)]['resonance'] = event_data
            if event_id == 74: FL_Channels[str(T_FL_CurrentChannel)]['preamp'] = event_data
            if event_id == 75: FL_Channels[str(T_FL_CurrentChannel)]['decay'] = event_data
            if event_id == 76: FL_Channels[str(T_FL_CurrentChannel)]['attack'] = event_data
            if event_id == 85: FL_Channels[str(T_FL_CurrentChannel)]['stdel'] = event_data
            if event_id == 131: FL_Channels[str(T_FL_CurrentChannel)]['fxsine'] = event_data
            if event_id == 70: FL_Channels[str(T_FL_CurrentChannel)]['fadestereo'] = event_data
            if event_id == 22: FL_Channels[str(T_FL_CurrentChannel)]['mixslicenum'] = event_data
            if event_id == 219: FL_Channels[str(T_FL_CurrentChannel)]['basicparams'] = event_data
            if event_id == 229: FL_Channels[str(T_FL_CurrentChannel)]['ofslevels'] = event_data
            if event_id == 221: FL_Channels[str(T_FL_CurrentChannel)]['poly'] = event_data
            if event_id == 215: FL_Channels[str(T_FL_CurrentChannel)]['params'] = event_data
            if event_id == 132: FL_Channels[str(T_FL_CurrentChannel)]['cutcutby'] = event_data
            if event_id == 144: FL_Channels[str(T_FL_CurrentChannel)]['layerflags'] = event_data
            if event_id == 145: FL_Channels[str(T_FL_CurrentChannel)]['filternum'] = event_data
            if event_id == 143: FL_Channels[str(T_FL_CurrentChannel)]['sampleflags'] = event_data
            if event_id == 20: FL_Channels[str(T_FL_CurrentChannel)]['looptype'] = event_data
            if event_id == 135: FL_Channels[str(T_FL_CurrentChannel)]['middlenote'] = event_data
            if event_id == 196: FL_Channels[str(T_FL_CurrentChannel)]['samplefilename'] = event_data.decode('utf-16le').rstrip('\x00\x00')
        else:
            if event_id == 149: 
                T_FL_FXColor = event_data
                #print('FXColor:', T_FL_FXColor)
            if event_id == 95: 
                T_FL_FXIcon = event_data
                #print('FXIcon:', T_FL_FXIcon)
            if event_id == 236: 
                T_FL_FXNum += 1
                #print('FXParams, Num', T_FL_FXNum)
                FL_Mixer[str(T_FL_FXNum)]['color'] = T_FL_FXColor
                FL_Mixer[str(T_FL_FXNum)]['icon'] = T_FL_FXIcon
                FL_Mixer[str(T_FL_FXNum)]['slots'] = {}
                FL_Mixer[str(T_FL_FXNum)]['data'] = event_data
                FXSlots = [{},{},{},{},{},{},{},{},{},{}]
                FXPlugin = None
                T_FL_FXColor = None
                T_FL_FXIcon = None
            if event_id == 201: 
                event_text = event_data.decode('utf-16le').rstrip('\x00\x00')
                #print('\\__DefPluginName:', event_text)
                DefPluginName = event_text
            if event_id == 212: 
                #print('\\__NewPlugin')
                FXPlugin = {}
                FXPlugin['plugin'] = DefPluginName
                FXPlugin['data'] = event_data
            if event_id == 155: FXPlugin['icon'] = event_data
            if event_id == 128: FXPlugin['color'] = event_data
            if event_id == 203: FXPlugin['name'] = event_data.decode('utf-16le').rstrip('\x00\x00')
            if event_id == 98: #FXToSlotNum
                FL_Mixer[str(T_FL_FXNum)]['slots'][event_data] = FXPlugin
                FXPlugin = None
            if event_id == 213: FXPlugin['pluginparams'] = event_data
            if event_id == 235: FL_Mixer[str(T_FL_FXNum)]['routing'] = deconstruct_fxrouting(event_data)
            if event_id == 154: FL_Mixer[str(T_FL_FXNum)]['inchannum'] = event_data
            if event_id == 147: FL_Mixer[str(T_FL_FXNum)]['outchannum'] = event_data
            if event_id == 204: 
                event_text = event_data.decode('utf-16le').rstrip('\x00\x00')
                #print('\\__FXName:', event_text)
                FL_Mixer[str(T_FL_FXNum)]['name'] = event_text

    output = {}
    FL_Main['ppq'] = flp_ppq
    output['FL_Main'] = FL_Main
    output['FL_Patterns'] = FL_Patterns
    output['FL_Channels'] = FL_Channels
    output['FL_Mixer'] = FL_Mixer
    output['FL_Tracks'] = FL_Tracks
    output['FL_Arrangements'] = FL_Arrangements
    output['FL_TimeMarkers'] = FL_TimeMarkers
    return output

# ------------- reconstruct -------------
def reconstruct_flevent(FLdt_bytes, value, data):
    if value <= 63 and value >= 0: # int8
        FLdt_bytes.write(value.to_bytes(1, "little"))
        FLdt_bytes.write(data.to_bytes(1, "little"))
    if value <= 127 and value >= 64 : # int16
        FLdt_bytes.write(value.to_bytes(1, "little"))
        FLdt_bytes.write(data.to_bytes(2, "little"))
    if value <= 191 and value >= 128 : # int32
        FLdt_bytes.write(value.to_bytes(1, "little"))
        FLdt_bytes.write(data.to_bytes(4, "little"))
    if value <= 224 and value >= 192 : # text
        FLdt_bytes.write(value.to_bytes(1, "little"))
        FLdt_bytes.write(varint.encode(len(data)))
        FLdt_bytes.write(data)
    if value <= 255 and value >= 225 : # data
        FLdt_bytes.write(value.to_bytes(1, "little"))
        FLdt_bytes.write(varint.encode(len(data)))
        FLdt_bytes.write(data)
def reconstruct_arrangement(data_FLdt, arrangements):
    for arrangement in arrangements:
        #print(arrangements[arrangement])
        reconstruct_flevent(data_FLdt, 99, int(arrangement)) #NewArrangement
        if 'name' in arrangements[arrangement]:
            reconstruct_flevent(data_FLdt, 241, arrangements[arrangement]['name'].encode('utf-16le') + b'\x00\x00') #ArrangementName
        placements = arrangements[arrangement]['items']
        BytesIO_arrangement = BytesIO()
        for item in placements:
            #print(singlenote)
            BytesIO_arrangement.write(item['position'].to_bytes(4, 'little'))
            BytesIO_arrangement.write(item['patternbase'].to_bytes(2, 'little'))
            BytesIO_arrangement.write(item['itemindex'].to_bytes(2, 'little'))
            BytesIO_arrangement.write(item['length'].to_bytes(4, 'little'))
            BytesIO_arrangement.write(item['trackindex'].to_bytes(4, 'little'))
            BytesIO_arrangement.write(item['unknown1'].to_bytes(2, 'little'))
            BytesIO_arrangement.write(item['flags'].to_bytes(2, 'little'))
            BytesIO_arrangement.write(item['unknown2'].to_bytes(2, 'little'))
            BytesIO_arrangement.write(item['unknown3'].to_bytes(2, 'little'))
            if 'startoffset' in item: BytesIO_arrangement.write(item['startoffset'].to_bytes(4, 'little'))
            else: BytesIO_arrangement.write(b'\xff\xff\xff\xff')
            if 'endoffset' in item: BytesIO_arrangement.write(item['endoffset'].to_bytes(4, 'little'))
            else: BytesIO_arrangement.write(b'\xff\xff\xff\xff')
        BytesIO_arrangement.seek(0)
        reconstruct_flevent(data_FLdt, 233, BytesIO_arrangement.read()) #PlayListItems
def reconstruct_timemarkers(data_FLdt, timemarkers):
    for timemarker in timemarkers:
        timemarker_item = timemarkers[timemarker]
        timemarkertype = timemarker_item['type'] << 24
        timemarkertime = timemarker_item['pos']
        reconstruct_flevent(data_FLdt, 148, timemarkertype+timemarkertime)
        if 'numerator' in timemarker_item: reconstruct_flevent(data_FLdt, 33, timemarker_item['numerator'])
        else: reconstruct_flevent(data_FLdt, 33, 4)
        if 'denominator' in timemarker_item: reconstruct_flevent(data_FLdt, 34, timemarker_item['denominator'])
        else: reconstruct_flevent(data_FLdt, 34, 4)
        if 'name' in timemarker_item: reconstruct_flevent(data_FLdt, 205, timemarker_item['name'].encode('utf-16le') + b'\x00\x00')
        else: reconstruct_flevent(data_FLdt, 205, b'\x20\x00\x00\x00')
def reconstruct_channels(data_FLdt, channels):
    for channel in channels:
        reconstruct_flevent(data_FLdt, 64, int(channel)) #NewChan
        reconstruct_flevent(data_FLdt, 21, channels[channel]['type']) #ChanType
        reconstruct_flevent(data_FLdt, 201, channels[channel]['plugin'].encode('utf-16le') + b'\x00\x00') #DefPluginName
        reconstruct_flevent(data_FLdt, 212, channels[channel]['chandata']) #NewPlugin
        reconstruct_flevent(data_FLdt, 203, channels[channel]['name'].encode('utf-16le') + b'\x00\x00') #PluginName
        reconstruct_flevent(data_FLdt, 155, channels[channel]['icon']) #PluginIcon
        reconstruct_flevent(data_FLdt, 128, channels[channel]['color']) #Color
        if 'pluginparams' in channels[channel]: reconstruct_flevent(data_FLdt, 213, channels[channel]['pluginparams']) #PluginParams
        if 'enabled' in channels[channel]: reconstruct_flevent(data_FLdt, 0, channels[channel]['enabled']) #Enabled
        if 'delay' in channels[channel]: reconstruct_flevent(data_FLdt, 209, channels[channel]['delay']) #Delay
        if 'delayreso' in channels[channel]: reconstruct_flevent(data_FLdt, 138, channels[channel]['delayreso']) #DelayReso
        if 'reverb' in channels[channel]: reconstruct_flevent(data_FLdt, 139, channels[channel]['reverb']) #Reverb
        if 'shiftdelay' in channels[channel]: reconstruct_flevent(data_FLdt, 89, channels[channel]['shiftdelay']) #ShiftDelay
        if 'fx' in channels[channel]: reconstruct_flevent(data_FLdt, 69, channels[channel]['fx']) #FX
        if 'fx3' in channels[channel]: reconstruct_flevent(data_FLdt, 86, channels[channel]['fx3']) #FX3
        if 'cutoff' in channels[channel]: reconstruct_flevent(data_FLdt, 71, channels[channel]['cutoff']) #CutOff
        if 'resonance' in channels[channel]: reconstruct_flevent(data_FLdt, 83, channels[channel]['resonance']) #Resonance
        if 'preamp' in channels[channel]: reconstruct_flevent(data_FLdt, 74, channels[channel]['preamp']) #PreAmp
        if 'decay' in channels[channel]: reconstruct_flevent(data_FLdt, 75, channels[channel]['decay']) #Decay
        if 'attack' in channels[channel]: reconstruct_flevent(data_FLdt, 76, channels[channel]['attack']) #Attack
        if 'stdel' in channels[channel]: reconstruct_flevent(data_FLdt, 85, channels[channel]['stdel']) #StDel
        if 'fxsine' in channels[channel]: reconstruct_flevent(data_FLdt, 131, channels[channel]['fxsine']) #FXSine
        if 'fadestereo' in channels[channel]: reconstruct_flevent(data_FLdt, 70, channels[channel]['fadestereo']) #Fade_Stereo
        if 'mixslicenum' in channels[channel]: reconstruct_flevent(data_FLdt, 22, channels[channel]['mixslicenum']) #MixSliceNum
        if 'basicparams' in channels[channel]: reconstruct_flevent(data_FLdt, 219, channels[channel]['basicparams']) #BasicChanParams
        if 'ofslevels' in channels[channel]: reconstruct_flevent(data_FLdt, 229, channels[channel]['ofslevels']) #BasicChanParams
        if 'poly' in channels[channel]: reconstruct_flevent(data_FLdt, 221, channels[channel]['poly']) #ChanPoly
        if 'params' in channels[channel]: reconstruct_flevent(data_FLdt, 215, channels[channel]['params']) #ChanParams
        if 'cutcutby' in channels[channel]: reconstruct_flevent(data_FLdt, 132, channels[channel]['cutcutby']) #CutCutBy
        if 'layerflags' in channels[channel]: reconstruct_flevent(data_FLdt, 144, channels[channel]['layerflags']) #LayerFlags
        if 'filternum' in channels[channel]: reconstruct_flevent(data_FLdt, 145, channels[channel]['filternum']) #ChanFilterNum
        reconstruct_flevent(data_FLdt, 32, 0)
        if 'envlfo_pan' in channels[channel]: reconstruct_flevent(data_FLdt, 218, channels[channel]['envlfo_pan']) #Envelope
        else: reconstruct_flevent(data_FLdt, 218, b'\x00\x00\x00\x00\x00\x00\x00\x00d\x00\x00\x00 N\x00\x00 N\x00\x000u\x00\x002\x00\x00\x00 N\x00\x00\x00\x00\x00\x00d\x00\x00\x00 N\x00\x00\x00\x00\x00\x00\xb6\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',)
        if 'envlfo_vol' in channels[channel]: reconstruct_flevent(data_FLdt, 218, channels[channel]['envlfo_vol']) #Envelope
        else: reconstruct_flevent(data_FLdt, 218, b'\x00\x00\x00\x00\x00\x00\x00\x00d\x00\x00\x00 N\x00\x00 N\x00\x000u\x00\x002\x00\x00\x00 N\x00\x00\x00\x00\x00\x00d\x00\x00\x00 N\x00\x00\x00\x00\x00\x00\xb6\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',)
        if 'envlfo_modx' in channels[channel]: reconstruct_flevent(data_FLdt, 218, channels[channel]['envlfo_modx']) #Envelope
        else: reconstruct_flevent(data_FLdt, 218, b'\x00\x00\x00\x00\x00\x00\x00\x00d\x00\x00\x00 N\x00\x00 N\x00\x000u\x00\x002\x00\x00\x00 N\x00\x00\x00\x00\x00\x00d\x00\x00\x00 N\x00\x00\x00\x00\x00\x00\xb6\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',)
        if 'envlfo_mody' in channels[channel]: reconstruct_flevent(data_FLdt, 218, channels[channel]['envlfo_mody']) #Envelope
        else: reconstruct_flevent(data_FLdt, 218, b'\x00\x00\x00\x00\x00\x00\x00\x00d\x00\x00\x00 N\x00\x00 N\x00\x000u\x00\x002\x00\x00\x00 N\x00\x00\x00\x00\x00\x00d\x00\x00\x00 N\x00\x00\x00\x00\x00\x00\xb6\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',)
        if 'envlfo_pitch' in channels[channel]: reconstruct_flevent(data_FLdt, 218, channels[channel]['envlfo_pitch']) #Envelope
        else: reconstruct_flevent(data_FLdt, 218, b'\x00\x00\x00\x00\x00\x00\x00\x00d\x00\x00\x00 N\x00\x00 N\x00\x000u\x00\x002\x00\x00\x00 N\x00\x00\x00\x00\x00\x00d\x00\x00\x00 N\x00\x00\x00\x00\x00\x00\xb6\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',)
        if 'sampleflags' in channels[channel]: reconstruct_flevent(data_FLdt, 143, channels[channel]['sampleflags']) #SampleFlags
        if 'looptype' in channels[channel]: reconstruct_flevent(data_FLdt, 20, channels[channel]['looptype']) #LoopType
        if 'middlenote' in channels[channel]: reconstruct_flevent(data_FLdt, 135, channels[channel]['middlenote']) #MiddleNote
        if 'samplefilename' in channels[channel]: reconstruct_flevent(data_FLdt, 196, channels[channel]['samplefilename'].encode('utf-16le') + b'\x00\x00') #SampleFileName
        #print(channel)
def reconstruct_patterns(data_FLdt, patterns):
    for pattern in patterns:
        reconstruct_flevent(data_FLdt, 65, int(pattern)) #NewPat
        #print(pattern)
        patternlistdata = patterns[str(pattern)]
        if 'automation' in patternlistdata:
            autopoint = patternlistdata['automation']
            BytesIO_autodata = BytesIO()
            for singleautopoint in autopoint:
                #print(singleautopoint)
                BytesIO_autodata.write(singleautopoint['pos'].to_bytes(4, 'little'))
                BytesIO_autodata.write(singleautopoint['control'])
                BytesIO_autodata.write(singleautopoint['value'])
            BytesIO_autodata.seek(0)
            reconstruct_flevent(data_FLdt, 223, BytesIO_autodata.read()) #AutomationData
        if 'notes' in patternlistdata:
            notelist = patternlistdata['notes']
            BytesIO_notedata = BytesIO()
            for singlenote in notelist:
                #print(singlenote)
                BytesIO_notedata.write(singlenote['pos'].to_bytes(4, 'little'))
                BytesIO_notedata.write(singlenote['flags'].to_bytes(2, 'little'))
                BytesIO_notedata.write(singlenote['rack'].to_bytes(2, 'little'))
                BytesIO_notedata.write(singlenote['dur'].to_bytes(4, 'little'))
                BytesIO_notedata.write(singlenote['key'].to_bytes(4, 'little'))
                BytesIO_notedata.write(singlenote['finep'].to_bytes(1, 'little'))
                BytesIO_notedata.write(singlenote['u1'].to_bytes(1, 'little'))
                BytesIO_notedata.write(singlenote['rel'].to_bytes(1, 'little'))
                BytesIO_notedata.write(singlenote['midich'].to_bytes(1, 'little'))
                BytesIO_notedata.write(singlenote['pan'].to_bytes(1, 'little'))
                BytesIO_notedata.write(singlenote['velocity'].to_bytes(1, 'little'))
                BytesIO_notedata.write(singlenote['mod_x'].to_bytes(1, 'little'))
                BytesIO_notedata.write(singlenote['mod_y'].to_bytes(1, 'little'))
            BytesIO_notedata.seek(0)
            reconstruct_flevent(data_FLdt, 224, BytesIO_notedata.read()) #PatternNotes
        if 'color' in patternlistdata:
            reconstruct_flevent(data_FLdt, 150, patternlistdata['color']) #PatColor
def reconstruct_trackinfo(data_FLdt, trackinfo):
    for i in range(1,500):
        if str(i) in trackinfo:
            trkparams = trackinfo[str(i)]
            fltrki_color = 5656904
            fltrki_icon = 0
            fltrki_enabled = 1
            fltrki_height = 1.0
            fltrki_lockedtocontent = 255
            fltrki_motion = 16777215
            fltrki_press = 0
            fltrki_triggersync = 0
            fltrki_queued = 5
            fltrki_tolerant = 0
            fltrki_positionSync = 1
            fltrki_grouped = 0
            fltrki_locked = 0
            if 'color' in trkparams: fltrki_color = trkparams['color']
            if 'icon' in trkparams: fltrki_icon = trkparams['icon']
            if 'enabled' in trkparams: fltrki_enabled = trkparams['enabled']
            if 'height' in trkparams: fltrki_height = trkparams['height']
            if 'lockedtocontent' in trkparams: fltrki_lockedtocontent = trkparams['lockedtocontent']
            if 'motion' in trkparams: fltrki_motion = trkparams['motion']
            if 'press' in trkparams: fltrki_press = trkparams['press']
            if 'triggersync' in trkparams: fltrki_triggersync = trkparams['triggersync']
            if 'queued' in trkparams: fltrki_queued = trkparams['queued']
            if 'tolerant' in trkparams: fltrki_tolerant = trkparams['tolerant']
            if 'positionSync' in trkparams: fltrki_positionSync = trkparams['positionSync']
            if 'grouped' in trkparams: fltrki_grouped = trkparams['grouped']
            if 'locked' in trkparams: fltrki_locked = trkparams['locked']
            BytesIO_trackinfo = BytesIO()
            BytesIO_trackinfo.write(i.to_bytes(4, "little"))
            BytesIO_trackinfo.write(fltrki_color.to_bytes(4, "little"))
            BytesIO_trackinfo.write(fltrki_icon.to_bytes(4, "little"))
            BytesIO_trackinfo.write(fltrki_enabled.to_bytes(1, "little"))
            BytesIO_trackinfo.write(struct.pack('<f', fltrki_height))
            BytesIO_trackinfo.write(fltrki_lockedtocontent.to_bytes(1, "little"))
            BytesIO_trackinfo.write(fltrki_motion.to_bytes(4, "little"))
            BytesIO_trackinfo.write(fltrki_press.to_bytes(4, "little"))
            BytesIO_trackinfo.write(fltrki_triggersync.to_bytes(4, "little"))
            BytesIO_trackinfo.write(fltrki_queued.to_bytes(4, "little"))
            BytesIO_trackinfo.write(fltrki_tolerant.to_bytes(4, "little"))
            BytesIO_trackinfo.write(fltrki_positionSync.to_bytes(4, "little"))
            BytesIO_trackinfo.write(fltrki_grouped.to_bytes(1, "little"))
            BytesIO_trackinfo.write(fltrki_locked.to_bytes(1, "little"))
            BytesIO_trackinfo.seek(0)
            reconstruct_flevent(data_FLdt, 238, BytesIO_trackinfo.read())
def reconstruct_mixer(data_FLdt, mixer):
    for i in range(0,127):
        slotnum = 0
        fltrki_color = None
        fltrki_icon = None
        fltrki_slots = {0: None, 1: None, 2: None, 3: None, 4: None, 5: None, 6: None, 7: None, 8: None, 9: None}
        fltrki_data = b'\x00\x00\x00\x00L\x00\x00\x00\x00\x00\x00\x00'
        fltrki_routing = [0]
        fltrki_inchannum = 4294967295
        fltrki_outchannum = 4294967295
        if str(i) in mixer:
            fxparams = mixer[str(i)]
            if 'color' in fxparams: fltrki_color = fxparams['color']
            if 'icon' in fxparams: fltrki_icon = fxparams['icon']
            if 'slots' in fxparams: fltrki_slots = fxparams['slots']
            if 'data' in fxparams: fltrki_data = fxparams['data']
            if 'routing' in fxparams: fltrki_routing = fxparams['routing']
            if 'inchannum' in fxparams: fltrki_inchannum = fxparams['inchannum']
            if 'outchannum' in fxparams: fltrki_outchannum = fxparams['outchannum']
        reconstruct_flevent(data_FLdt, 236, fltrki_data)
        for fltrki_slot in fltrki_slots:
            fxslotL = fltrki_slots[fltrki_slot]
            if fxslotL != None:
                print(fxslotL)
                reconstruct_flevent(data_FLdt, 201, fxslotL['plugin'].encode('utf-16le') + b'\x00\x00')
                reconstruct_flevent(data_FLdt, 212, fxslotL['data'])
                if 'name' in fxslotL: reconstruct_flevent(data_FLdt, 203, fxslotL['name'].encode('utf-16le') + b'\x00\x00')
                if 'icon' in fxslotL: reconstruct_flevent(data_FLdt, 155, fxslotL['icon'])
                if 'color' in fxslotL: reconstruct_flevent(data_FLdt, 128, fxslotL['color'])
                reconstruct_flevent(data_FLdt, 213, fxslotL['pluginparams'])
            reconstruct_flevent(data_FLdt, 98, slotnum)
            slotnum += 1

        fxrouting_fl = []
        for i in range(0,127):
            fxrouting_fl.append(0)
        for route in fxparams['routing']:
            fxrouting_fl[route] = 1
        reconstruct_flevent(data_FLdt, 235, bytearray(fxrouting_fl))
        reconstruct_flevent(data_FLdt, 154, fltrki_inchannum)
        reconstruct_flevent(data_FLdt, 147, fltrki_outchannum)

def reconstruct(FLP_Data, outputfile):
    flpout = open(outputfile, 'wb')
    numofchannels = len(FLP_Data['FL_Channels'])
    #FLhd
    data_FLhd = BytesIO()
    data_FLhd.write(numofchannels.to_bytes(3, 'big'))
    data_FLhd.write(b'\x00')
    data_FLhd.write(FLP_Data['FL_Main']['ppq'].to_bytes(2, 'little'))

    #FLdt
    data_FLdt = BytesIO()
    reconstruct_flevent(data_FLdt, 199, '20.7.2.1852'.encode('utf8') + b'\x00')
    reconstruct_flevent(data_FLdt, 159, 1852)
    reconstruct_flevent(data_FLdt, 37, 1)
    reconstruct_flevent(data_FLdt, 200, b'\x00\x00')
    reconstruct_flevent(data_FLdt, 156, int(FLP_Data['FL_Main']['Tempo']*1000))
    reconstruct_flevent(data_FLdt, 67, 1) #CurrentPatNum
    reconstruct_flevent(data_FLdt, 9, 1) #LoopActive
    reconstruct_flevent(data_FLdt, 11, int(FLP_Data['FL_Main']['Shuffle'])) #Shuffle 
    reconstruct_flevent(data_FLdt, 80, int(FLP_Data['FL_Main']['MainPitch'])) #MainPitch
    reconstruct_flevent(data_FLdt, 17, int(FLP_Data['FL_Main']['Numerator'])) #Numerator
    reconstruct_flevent(data_FLdt, 18, int(FLP_Data['FL_Main']['Denominator'])) #Denominator
    reconstruct_flevent(data_FLdt, 35, 1)
    reconstruct_flevent(data_FLdt, 23, 1) #PanVolumeTab
    reconstruct_flevent(data_FLdt, 10, int(FLP_Data['FL_Main']['ShowInfo'])) #ShowInfo
    reconstruct_flevent(data_FLdt, 194, FLP_Data['FL_Main']['Title'].encode('utf-16le') + b'\x00\x00')
    reconstruct_flevent(data_FLdt, 206, FLP_Data['FL_Main']['Genre'].encode('utf-16le') + b'\x00\x00')
    reconstruct_flevent(data_FLdt, 207, FLP_Data['FL_Main']['Author'].encode('utf-16le') + b'\x00\x00')
    reconstruct_flevent(data_FLdt, 202, FLP_Data['FL_Main']['ProjectDataPath'].encode('utf-16le') + b'\x00\x00')
    reconstruct_flevent(data_FLdt, 195, FLP_Data['FL_Main']['Comment'].encode('utf-16le') + b'\x00\x00')
    #reconstruct_flevent(data_FLdt, 197, FLP_Data['FL_Main']['URL'].encode('utf-16le') + b'\x00\x00')
    reconstruct_patterns(data_FLdt, FLP_Data['FL_Patterns'])
    reconstruct_channels(data_FLdt, FLP_Data['FL_Channels'])
    reconstruct_arrangement(data_FLdt, FLP_Data['FL_Arrangements'])
    reconstruct_timemarkers(data_FLdt, FLP_Data['FL_TimeMarkers'])
    reconstruct_trackinfo(data_FLdt, FLP_Data['FL_Tracks'])
    reconstruct_flevent(data_FLdt, 100, 0)
    reconstruct_flevent(data_FLdt, 29, 1)
    reconstruct_flevent(data_FLdt, 39, 0)
    reconstruct_flevent(data_FLdt, 31, 0)
    reconstruct_flevent(data_FLdt, 38, 1)
    reconstruct_mixer(data_FLdt, FLP_Data['FL_Mixer'])

    data_FLhd.seek(0)
    flpout.write(b'FLhd')
    data_FLhd_out = data_FLhd.read()
    flpout.write(len(data_FLhd_out).to_bytes(4, 'little'))
    flpout.write(data_FLhd_out)


    data_FLdt.seek(0)
    flpout.write(b'FLdt')
    data_FLdt_out = data_FLdt.read()
    flpout.write(len(data_FLdt_out).to_bytes(4, 'little'))
    flpout.write(data_FLdt_out)

