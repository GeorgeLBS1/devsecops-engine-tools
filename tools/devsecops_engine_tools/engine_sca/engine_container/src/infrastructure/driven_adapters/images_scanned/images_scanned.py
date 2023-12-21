import os

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.images_scanned_gateway import ImagesScannedGateway



class ImagesScanned(ImagesScannedGateway):

    def get_images_already_scanned_file(self):
         """
         Get the file name of images already been scanned.
         """
         return 'scanned_images.txt'
    
    def get_images_already_scanned(self, file_name):
        """
        Create images scanned file if it does not exist and get the images that have already been scanned.
        """
        scanned_images_file = os.path.join(os.getcwd(), file_name)
        # Check if the file exists; if not, create it
        if not os.path.exists(scanned_images_file):
            open(scanned_images_file, 'w').close()
        with open(scanned_images_file, 'r') as file:
                images_scanned = file.read().splitlines()
        return images_scanned