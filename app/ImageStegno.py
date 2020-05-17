from PIL import Image as img
import binascii
from os.path import getsize , splitext
from app import app
from flask import flash, redirect, url_for


#Credit too https://github.com/xandhiller/steg/blob/master/encodeImage.py for the ideas of how to use the classes i really like it :)
#Credit too https://www.youtube.com/watch?v=q3eOOMx5qoo for showing hexlify 

END_MSG_RGB = '1111111111111110'
#End message buffer this is used to understand when we have ended our message in decode and encode

class text:
    def __init__(self,TextFileName):
        TextFile = open("/home/hainzz/Software-Devlopment/app/static/Stegno/Encode/Messages/" + TextFileName,"rb") 
        self.RawData = TextFile.read()
        self.TextBinary = self.GetBinary() # Gets the binary of the text data
        self.Payload = self.TextBinary + END_MSG_RGB #This here is the delimeter that signifies the end of the message
        self.Size = getsize("/home/hainzz/Software-Devlopment/app/static/Stegno/Encode/Messages/" + TextFileName) * 8 + 32 #Number of bits in the file

    def GetBinary(self):
        binary = bin(int(binascii.hexlify(self.RawData), 16))
        return binary[2:]

class image:
    def __init__(self,ImageFileName):
        self.image = img.open("/home/hainzz/Software-Devlopment/app/static/Stegno/Encode/Images/" + ImageFileName)
        self.image_type = self.image.format #Obtains format of the image
        self.MaxSize = self.image.size[0] * self.image.size[1]
        self.Image_Mode =  self.image.mode # Mode means RGB etc
        self.FileName = ImageFileName

def Determine_Hide_Func(Image,Text):
    #Determines whether the image type is suitable for encoding each image type works differently therefore different functions are needed
    if Image.Image_Mode == 'L':
        L_Image_Mode_Hide(Image,Text)
    if Image.Image_Mode == 'RGB':
        RBG_Image_Mode_Hide(Image,Text)
    if Image.Image_Mode == 'RGBA':
        RGBA_Image_Mode_Hide(Image,Text)
    elif Image.Image_Mode == '1':
        #Note these flash redirects are used throughout in order to send any error messages back to the user
        flash('Image mode of 1 is invalid')
        return redirect(url_for("ImageEncode"))
    else:
        flash('Could not determine image mode')
        return redirect(url_for("ImageEncode"))


def DetermineStegnoPossible(Image,Text):
    # This determines whether the image has enough bits too actually encode the message sent by the user
    if Image.Image_Mode =='L':
        if Text.Size >= Image.MaxSize:
            flash('Your message is too large to hide in the image')
            return redirect(url_for("ImageEncode"))
    if Image.Image_Mode in ('RGB','RGBA'):
        if Text.Size >= Image.MaxSize*3:
            flash('Your message is too large to hide in the image')
            return redirect(url_for("ImageEncode"))



def L_Image_Mode_Hide(Image,Text):
    NewImage = img.new("L", (Image.image.size[0], Image.image.size[1]), "white")
    #Creates a NewImage with the mode of L and with the size of the orginal image
    Bitstream = list(Text.Payload)
    #This turns the bitstream into a list so we can manipulate
    for i in range(Image.image.size[0]):
        for j in range(Image.image.size[1]):
            #These for loops run through every pixel within the image
            ImRed= Image.image.getpixel((i,j))
            if len(Bitstream) != 0:
                # If we havent hit the end of the bitstream keep replacing bits else end (only LSB is changed to preserve image)
                NewBit = Bitstream[0]
                ImRed = Replace_Bit(ImRed,NewBit)
                del Bitstream[0]
            NewImage.putpixel((i,j),(ImRed))
            # This puts the pixel into the new image we are creating
    NewImage.save("/home/hainzz/Software-Devlopment/app/static/Stegno/Encode/EncodedImages/" + "Encoded" + Image.FileName)
    # Saves the image to the following directory note this is configured for my ubuntu VM
    

def Replace_Bit(ImageRedValue,RedLSBValue):
    BinaryValue = list(bin(ImageRedValue))
    BinaryValue[-1:] = RedLSBValue
    # This functions replaces the LSB value of every bit sent
    return int(''.join(BinaryValue),2)

def RBG_Image_Mode_Hide(Image,Text):
    NewImage = img.new("RGB", (Image.image.size[0], Image.image.size[1]), "white")
    Bitstream = list(Text.Payload)
    #This function is very similar to L however we are now replacing RGB values instead of a single LSB 
    for i in range(Image.image.size[0]):
        for j in range(Image.image.size[1]):
            ImRed, ImGreen, ImBlue = Image.image.getpixel((i,j))
            if len(Bitstream) != 0:
                NewBit = Bitstream[0]
                ImRed = Replace_Bit(ImRed,NewBit)
                del Bitstream[0]
            if len(Bitstream) != 0:
                NewBit = Bitstream[0]
                ImGreen = Replace_Bit(ImGreen,NewBit)
                del Bitstream[0]
            if len(Bitstream) != 0:
                NewBit = Bitstream[0]
                ImBlue = Replace_Bit(ImBlue,NewBit)
                del Bitstream[0]
            NewImage.putpixel((i,j),(ImRed,ImGreen,ImBlue))
    NewImage.save("/home/hainzz/Software-Devlopment/app/static/Stegno/Encode/EncodedImages/" + "Encoded" + Image.FileName)



#https://github.com/beatsbears/steg/blob/master/steg/steg_img.py Credit for showing me cool tricks and replacing bits and teaching my how to effectively use PIL

def RGBA_Image_Mode_Hide(Image,Text):
    NewImage = img.new("RGBA", (Image.image.size[0], Image.image.size[1]), "white")
    Bitstream = list(Text.Payload)
    for i in range(Image.image.size[0]):
        for j in range(Image.image.size[1]):
            ImRed, ImGreen, ImBlue, ImAmber = Image.image.getpixel((i,j)) #Despite not encoding amber values we still need to place them in our new image
            if len(Bitstream) != 0:
                NewBit = Bitstream[0]
                ImRed = Replace_Bit(ImRed,NewBit)
                del Bitstream[0]
            if len(Bitstream) != 0:
                NewBit = Bitstream[0]
                ImGreen = Replace_Bit(ImGreen,NewBit)
                del Bitstream[0]
            if len(Bitstream) != 0:
                NewBit = Bitstream[0]
                ImBlue = Replace_Bit(ImBlue,NewBit)
                del Bitstream[0]
            NewImage.putpixel((i,j),(ImRed,ImGreen,ImBlue,ImAmber))
    NewImage.save("/home/hainzz/Software-Devlopment/app/static/Stegno/Encode/EncodedImages/" + "Encoded" + Image.FileName)
    

def Determine_Show_Func(ImageFileName):
    #This functions determines whether the image inputted is of a valid type to decode
    EncryptedImage = img.open("/home/hainzz/Software-Devlopment/app/static/Stegno/Decode/Images/" + ImageFileName)
    Mode = EncryptedImage.mode
    if Mode == 'RGB':
        Message = Show_RBG_Encode(EncryptedImage)
        return Message
    if Mode == 'RGBA':
        Message = Show_RBGA_Encode(EncryptedImage)
        return Message
    if Mode == 'L':
        Message = Show_L_Encode(EncryptedImage)
        return Message
    elif Mode == '1':
        flash('Image mode of one is invalid')
        return redirect(url_for('ImageDecode'))
    else:
        flash('Could not determine image mode')
        return redirect(url_for('ImageDecode'))
    return Message

def Show_L_Encode(EncodedImage):
    EncodedBitStream = ''
    for i in range (EncodedImage.size[0]):
        for j in range (EncodedImage.size[1]):
            Red = EncodedImage.getpixel((i,j))
            EncodedBitStream = EncodedBitStream + (bin(Red)[-1:]) # Take LSB from Red 
            if EncodedBitStream[-16:] == (END_MSG_RGB): #Once we hit the buffer we know thats the end of the message therefore a string now needs to be returned
                return BinaryToString(EncodedBitStream[:-16]) 

def Show_RBGA_Encode(EncodedImage):
    EncodedBitStream = ''
    for i in range (EncodedImage.size[0]):
        for j in range (EncodedImage.size[1]):
            Red,Green,Blue,AmberVal = EncodedImage.getpixel((i,j))
            EncodedBitStream = EncodedBitStream + (bin(Red)[-1:]) # Take LSB from Red 
            if EncodedBitStream[-16:] == (END_MSG_RGB):
                return BinaryToString(EncodedBitStream[:-16]) 
            EncodedBitStream = EncodedBitStream + (bin(Green)[-1:])
            if EncodedBitStream[-16:] == (END_MSG_RGB):
                return BinaryToString(EncodedBitStream[:-16])
            EncodedBitStream = EncodedBitStream + (bin(Blue)[-1:])
            if EncodedBitStream[-16:] == (END_MSG_RGB):
                return BinaryToString(EncodedBitStream[:-16])
                

def BinaryToString(EncodedMessage):
    try:
        message = binascii.unhexlify('%x'  % (int('0b'+EncodedMessage,2))) #Converts the binary to text the 0%x is for padding purposes
    except binascii.Error:
        message = binascii.unhexlify('0%x'  % (int('0b'+EncodedMessage,2)))
    message = message.decode('utf-8')
    return message
  

def Show_RBG_Encode(EncodedImage):
    EncodedBitStream = ''
    for i in range (EncodedImage.size[0]):
        for j in range (EncodedImage.size[1]):
            Red,Green,Blue = EncodedImage.getpixel((i,j))
            EncodedBitStream = EncodedBitStream + (bin(Red)[-1:]) # Take LSB from Red 
            if EncodedBitStream[-16:] == (END_MSG_RGB):
                return BinaryToString(EncodedBitStream[:-16]) 
            EncodedBitStream = EncodedBitStream + (bin(Green)[-1:])
            if EncodedBitStream[-16:] == (END_MSG_RGB):
                return BinaryToString(EncodedBitStream[:-16])
            EncodedBitStream = EncodedBitStream + (bin(Blue)[-1:])
            if EncodedBitStream[-16:] == (END_MSG_RGB):
                return BinaryToString(EncodedBitStream[:-16])


def Encode(TextFile,ImageFile):
    #Names of both the image and the text file are passed
    Text= text(TextFile)
    Image=image(ImageFile)
    DetermineStegnoPossible(Image,Text)
    Determine_Hide_Func(Image,Text)

def Decode(ImageFile):
    Message = Determine_Show_Func(ImageFile)
    ImageFile = splitext(ImageFile)
    DecodedFile = open("/home/hainzz/Software-Devlopment/app/static/Stegno/Decode/DecodedMessages/" + "Decoded" + ImageFile[0] + ".txt" ,"w")
    # Writes the decoded message to a text file and saves it
    DecodedFile.write(Message)
    DecodedFile.close()

#Just ensures it dosent run unless we want it too
if __name__ == "__main__":
    pass