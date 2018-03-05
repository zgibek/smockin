
app.controller('ftpDashboardController', function($scope, $rootScope, $location, $http, utils, globalVars, restClient) {


    //
    // Constants
    var MockServerRunningStatus = globalVars.MockServerRunningStatus;
    var MockServerStoppedStatus = globalVars.MockServerStoppedStatus;
    var MockServerRestartStatus = globalVars.MockServerRestartStatus;


    //
    // Labels
    $scope.mockServerStatusLabel = 'FTP Mock Server Status:';
//  $scope.serverConfigLabel = '(edit settings)';
    $scope.noDataFoundMsg = 'No Data Found';
    $scope.mockServerRunning = MockServerRunningStatus;
    $scope.mockServerStopped = MockServerStoppedStatus;
    $scope.mockServerRestarting = MockServerRestartStatus;
    $scope.endpointsHeading = 'Simulated FTP Repositories';

    $scope.nameTableLabel = 'Username';
    $scope.dateCreatedTableLabel = 'Date Created';
    $scope.statusTableLabel = 'Status';
    $scope.actionTableLabel = 'Action';


    //
    // Buttons
    $scope.addEndpointButtonLabel = 'New FTP Repository';
    $scope.viewEndpointButtonLabel = 'View';


    //
    // Alerts
    function showAlert(msg, type) {
        $scope.$parent.showAlert(msg, type);
    }


    //
    // Data
    $scope.ftpServices = [];
    $scope.mockServerStatus = null;


    //
    // Scoped Functions
    $scope.doOpenFtpInfo = function(ftpData) {
        $rootScope.ftpEndpointData = ftpData;
        $location.path("/ftp_endpoint");
    };


    $scope.startFtpMockServer = function() {

        utils.showLoadingOverlay('Starting FTP Server');

        restClient.doPost($http, '/mockedserver/ftp/start', {}, function(status, data) {

            utils.hideLoadingOverlay();

            if (status == 200) {
                $scope.mockServerStatus = MockServerRunningStatus;
                showAlert("FTP Server Started (on port " + String(data.port) + ")", "success");
                return;
            }

            showAlert(globalVars.GeneralErrorMessage);
        });

    }

    $scope.stopFtpMockServer = function () {

        utils.showLoadingOverlay('Stopping FTP Server');

        restClient.doPost($http, '/mockedserver/ftp/stop', {}, function(status, data) {

            utils.hideLoadingOverlay();

            if (status == 204) {
                $scope.mockServerStatus = MockServerStoppedStatus;
                showAlert("FTP Server Stopped", "success");
                return;
            }

            showAlert(globalVars.GeneralErrorMessage);
        });

    }


    //
    // Internal Functions
    function checkFtpServerStatus() {

        restClient.doGet($http, '/mockedserver/ftp/status', function(status, data) {

            if (status != 200) {
                showAlert(globalVars.GeneralErrorMessage);
                return;
            }

            $scope.mockServerStatus = (data.running)?MockServerRunningStatus:MockServerStoppedStatus;
        });

    };

    /*
    function restartFtpMockServer(callback) {

        utils.showLoadingOverlay('Updating FTP Server');

        restClient.doPost($http, '/mockedserver/ftp/restart', {}, function(status, data) {

            if (status == 200) {
                callback(data.port);
                return;
            }

            callback();
        });

    }
    */

    function loadTableData() {

        $scope.ftpServices = [];

        restClient.doGet($http, '/ftpmock', function(status, data) {

            if (status != 200) {
                showAlert(globalVars.GeneralErrorMessage);
                return;
            }

            $scope.ftpServices = data;
        });

    }


    //
    // Init Page
    loadTableData();
    checkFtpServerStatus();

});
