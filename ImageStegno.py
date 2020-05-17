from PIL import Image as img
import binascii
from os.path import getsize


#Credit too https://github.com/xandhiller/steg/blob/master/encodeImage.py for the ideas of how to use the classes i really like it :)
#Credit too https://www.youtube.com/watch?v=q3eOOMx5qoo for showing hexlify 

END_MSG_RGB = '1111111111111110'

class text:
    def __init__(self):
        TextFile = open("Message.txt","rb") #TODO allow input of filenames
        self.RawData = TextFile.read()
        self.TextBinary = self.GetBinary()
        self.Payload = self.TextBinary + END_MSG_RGB #This here is the delimeter that signifies the end of the message
        self.Size = getsize("Message.txt") * 8 + 32 #Number of bits in the file

    def GetBinary(self):
        binary = bin(int(binascii.hexlify(self.RawData), 16))
        return binary[2:]

class image:
    def __init__(self):
        self.image = img.open("Test.png")
        self.image_type = self.image.format #TODO Check Image Formats as well as mode 
        self.MaxSize = self.image.size[0] * self.image.size[1]
        self.Image_Mode =  self.image.mode

def Determine_Hide_Func(Image,Text):
    if Image.Image_Mode == 'L':
        L_Image_Mode_Hide(Image,Text)
    if Image.Image_Mode == 'RGB':
        RBG_Image_Mode_Hide(Image,Text)
    if Image.Image_Mode == 'RGBA':
        RGBA_Image_Mode_Hide(Image,Text)
    elif Image.Image_Mode == '1':
        print('Image mode of one is invalid')
    else:
        print('Could not determine image mode')


def DetermineStegnoPossible(Image,Text):
    if Image.Image_Mode =='L':
        if Text.Size >= Image.MaxSize:
            print('Your message is too large to hide in the image')
            exit()
    if Image.Image_Mode in ('RGB','RGBA'):
        if Text.Size >= Image.MaxSize*3:
            print('Your message is too large to hide in the image')
            exit()



def L_Image_Mode_Hide(Image,Text):
    NewImage = img.new("L", (Image.image.size[0], Image.image.size[1]), "white")
    Bitstream = list(Text.Payload)
    for i in range(Image.image.size[0]):
        for j in range(Image.image.size[1]):
            ImRed= Image.image.getpixel((i,j))
            if len(Bitstream) != 0:
                NewBit = Bitstream[0]
                ImRed = Replace_Bit(ImRed,NewBit)
                del Bitstream[0]
            NewImage.putpixel((i,j),(ImRed))
    NewImage.save("EncodedImage.png")
    #TODO Better Saving Structure 

def Replace_Bit(ImageRedValue,RedLSBValue):
    BinaryValue = list(bin(ImageRedValue))
    BinaryValue[-1:] = RedLSBValue
    return int(''.join(BinaryValue),2)

def RBG_Image_Mode_Hide(Image,Text):
    NewImage = img.new("RGB", (Image.image.size[0], Image.image.size[1]), "white")
    Bitstream = list(Text.Payload)
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
    NewImage.save("EncodedImage.png")



#https://github.com/beatsbears/steg/blob/master/steg/steg_img.py Credit for showing me cool tricks and replacing bits and teaching my how to effectively use PIL

def RGBA_Image_Mode_Hide(Image,Text):
    NewImage = img.new("RGBA", (Image.image.size[0], Image.image.size[1]), "white")
    Bitstream = list(Text.Payload)
    for i in range(Image.image.size[0]):
        for j in range(Image.image.size[1]):
            ImRed, ImGreen, ImBlue, ImAmber = Image.image.getpixel((i,j))
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
    NewImage.save("EncodedImage.png")
    

def Determine_Show_Func():
    EncryptedImage = img.open("EncodedImage.png")
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
        print('Image mode of one is invalid')
    else:
        print('Could not determine image mode')
    return Message

def Show_L_Encode(EncodedImage):
    EncodedBitStream = ''
    for i in range (EncodedImage.size[0]):
        for j in range (EncodedImage.size[1]):
            Red = EncodedImage.getpixel((i,j))
            EncodedBitStream = EncodedBitStream + (bin(Red)[-1:]) # Take LSB from Red 
            if EncodedBitStream[-16:] == (END_MSG_RGB):
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
  message = binascii.unhexlify('%x'  % (int('0b'+EncodedMessage,2)))
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


def PrintMessage(Message):
    print('Success We found you a message ! :')
    print(Message)


if __name__ == "__main__":
    Encode_Or_Decode = input("E = ENCODE | D = DECODE ")
    if Encode_Or_Decode == "E":  
        Text = text()
        Image = image()  
        DetermineStegnoPossible(Image,Text)
        Determine_Hide_Func(Image,Text)
    elif Encode_Or_Decode == "D":         
        Message = Determine_Show_Func()
        PrintMessage(Message)